// Package resources provides real-time system resource monitoring for
// dynamic scan admission control and runtime backpressure.
//
// It reads Linux /proc files (meminfo, loadavg) and uses syscall.Statfs
// for disk space. All thresholds are configurable via environment variables.
package resources

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ── Resource Levels ──

// Level represents the system's current resource pressure.
type Level int

const (
	LevelOK       Level = iota // All good — admit scans, execute tools freely
	LevelCaution               // Resources thinning — block new scans, existing continue
	LevelCritical              // Danger zone — throttle heavy tool execution
)

func (l Level) String() string {
	switch l {
	case LevelOK:
		return "OK"
	case LevelCaution:
		return "CAUTION"
	case LevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ── System Stats ──

// SystemStats contains a snapshot of current system resources.
type SystemStats struct {
	CPUCores       int
	LoadAvg1m      float64
	MemTotalMB     int64
	MemAvailableMB int64
	DiskFreeMB     int64
}

// ── Thresholds (configurable via env vars) ──

// defaults are calibrated for a 12-core / 24GB workstation.
// Override with env vars for smaller/larger machines.
var (
	// CPU: percentage of cores that constitutes the threshold.
	// e.g., on 12 cores, 70% = load 8.4, 90% = load 10.8
	cpuCautionPct  = envFloat("XALGORIX_CPU_CAUTION_PCT", 70)
	cpuCriticalPct = envFloat("XALGORIX_CPU_CRITICAL_PCT", 90)

	// RAM: minimum free RAM in MB.
	ramCautionMB  = envInt64("XALGORIX_RAM_CAUTION_MB", 4096)  // 4 GB
	ramCriticalMB = envInt64("XALGORIX_RAM_CRITICAL_MB", 2048) // 2 GB

	// Disk: minimum free disk in MB.
	diskCautionMB  = envInt64("XALGORIX_DISK_CAUTION_MB", 2048) // 2 GB
	diskCriticalMB = envInt64("XALGORIX_DISK_CRITICAL_MB", 1024) // 1 GB

	// Hard ceiling on concurrent instances regardless of resources.
	maxInstances = envInt("XALGORIX_MAX_INSTANCES", 10)

	// Per-process memory limit for heavy tools (bytes).
	// Default 4 GB. Set to 0 to disable.
	HeavyToolMemLimitBytes = envInt64("XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB", 4096) * 1024 * 1024
)

// ── Public API ──

// GetStats returns a snapshot of current system resources.
func GetStats() SystemStats {
	stats := SystemStats{
		CPUCores: runtime.NumCPU(),
	}

	stats.LoadAvg1m = readLoadAvg()
	stats.MemTotalMB, stats.MemAvailableMB = readMemInfo()
	stats.DiskFreeMB = readDiskFree()

	return stats
}

// CurrentLevel evaluates the system's overall resource pressure.
// Returns the worst (highest) level across all resource dimensions.
func CurrentLevel() (Level, string) {
	stats := GetStats()
	level := LevelOK
	var reasons []string

	// ── CPU check ──
	cpuCautionLoad := float64(stats.CPUCores) * cpuCautionPct / 100
	cpuCriticalLoad := float64(stats.CPUCores) * cpuCriticalPct / 100

	if stats.LoadAvg1m >= cpuCriticalLoad {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("CPU critical: load %.1f ≥ %.1f (%d%% of %d cores)",
			stats.LoadAvg1m, cpuCriticalLoad, int(cpuCriticalPct), stats.CPUCores))
	} else if stats.LoadAvg1m >= cpuCautionLoad {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("CPU high: load %.1f ≥ %.1f (%d%% of %d cores)",
			stats.LoadAvg1m, cpuCautionLoad, int(cpuCautionPct), stats.CPUCores))
	}

	// ── RAM check ──
	if stats.MemAvailableMB < ramCriticalMB {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("RAM critical: %d MB free < %d MB min",
			stats.MemAvailableMB, ramCriticalMB))
	} else if stats.MemAvailableMB < ramCautionMB {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("RAM low: %d MB free < %d MB caution",
			stats.MemAvailableMB, ramCautionMB))
	}

	// ── Disk check ──
	if stats.DiskFreeMB < diskCriticalMB {
		level = maxLevel(level, LevelCritical)
		reasons = append(reasons, fmt.Sprintf("Disk critical: %d MB free < %d MB min",
			stats.DiskFreeMB, diskCriticalMB))
	} else if stats.DiskFreeMB < diskCautionMB {
		level = maxLevel(level, LevelCaution)
		reasons = append(reasons, fmt.Sprintf("Disk low: %d MB free < %d MB caution",
			stats.DiskFreeMB, diskCautionMB))
	}

	if len(reasons) == 0 {
		return LevelOK, fmt.Sprintf("OK — CPU: %.1f/%d cores, RAM: %d MB free, Disk: %d MB free",
			stats.LoadAvg1m, stats.CPUCores, stats.MemAvailableMB, stats.DiskFreeMB)
	}
	return level, strings.Join(reasons, "; ")
}

// CanAdmitScan decides whether a new scan instance should be started.
// Layer 1: admission control.
func CanAdmitScan(runningCount int) (bool, string) {
	// Hard ceiling check first
	if runningCount >= maxInstances {
		return false, fmt.Sprintf("hard limit: %d/%d instances running", runningCount, maxInstances)
	}

	level, reason := CurrentLevel()
	if level >= LevelCaution {
		return false, reason
	}

	return true, reason
}

// CanExecTool decides whether a tool can be executed right now.
// Layer 2: pre-exec throttle. Heavy tools are gated at LevelCaution,
// light tools only at LevelCritical.
func CanExecTool(isHeavy bool) (bool, string) {
	level, reason := CurrentLevel()
	if isHeavy && level >= LevelCaution {
		return false, reason
	}
	if !isHeavy && level >= LevelCritical {
		return false, reason
	}
	return true, reason
}

// WaitForResources blocks until resources drop below the required level,
// or until maxWait is exceeded. Returns true if resources became available,
// false if timed out (caller should proceed anyway to avoid deadlock).
func WaitForResources(isHeavy bool, maxWait time.Duration, toolName string) bool {
	deadline := time.Now().Add(maxWait)
	waited := false

	for time.Now().Before(deadline) {
		ok, _ := CanExecTool(isHeavy)
		if ok {
			if waited {
				log.Printf("[RESOURCES] Resources recovered — proceeding with %q", toolName)
			}
			return true
		}

		if !waited {
			_, reason := CurrentLevel()
			log.Printf("[THROTTLE] Waiting to exec %q — %s (max wait: %s)", toolName, reason, maxWait)
			waited = true
		}

		time.Sleep(5 * time.Second)
	}

	log.Printf("[THROTTLE] Timeout waiting for resources, proceeding with %q anyway", toolName)
	return false
}

// MaxInstances returns the configured hard ceiling.
func MaxInstances() int {
	return maxInstances
}

// ── Linux /proc readers ──

// readLoadAvg reads 1-minute load average from /proc/loadavg.
func readLoadAvg() float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		log.Printf("[RESOURCES] Cannot read /proc/loadavg: %v", err)
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return val
}

// readMemInfo reads total and available memory from /proc/meminfo.
func readMemInfo() (totalMB, availableMB int64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		log.Printf("[RESOURCES] Cannot read /proc/meminfo: %v", err)
		return 0, 0
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		// /proc/meminfo reports in kB
		switch fields[0] {
		case "MemTotal:":
			totalMB = val / 1024
		case "MemAvailable:":
			availableMB = val / 1024
		}
	}
	return totalMB, availableMB
}

// readDiskFree returns free disk space (in MB) for the root filesystem.
func readDiskFree() int64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		log.Printf("[RESOURCES] Cannot statfs /: %v", err)
		return 0
	}
	// Available blocks * block size → bytes → MB
	return int64(stat.Bavail) * int64(stat.Bsize) / (1024 * 1024)
}

// ── Env var helpers ──

func envFloat(key string, defaultVal float64) float64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		log.Printf("[RESOURCES] Invalid %s=%q, using default %.1f", key, s, defaultVal)
		return defaultVal
	}
	return v
}

func envInt64(key string, defaultVal int64) int64 {
	s := os.Getenv(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		log.Printf("[RESOURCES] Invalid %s=%q, using default %d", key, s, defaultVal)
		return defaultVal
	}
	return v
}

func envInt(key string, defaultVal int) int {
	return int(envInt64(key, int64(defaultVal)))
}

// max returns the larger of two Levels.
func maxLevel(a, b Level) Level {
	if a > b {
		return a
	}
	return b
}
