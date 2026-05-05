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

// ── Thresholds (auto-scaled by init, overridable via env vars) ──
//
// IMPORTANT: Defaults are computed dynamically at startup based on actual
// system resources (CPU cores, total RAM). This ensures safe operation on
// both a 1-core/4GB VPS and a 12-core/24GB workstation without manual tuning.
//
// Override any value with its environment variable.
var (
	// CPU: percentage of cores that constitutes the threshold.
	// e.g., on 12 cores, 70% = load 8.4, 90% = load 10.8
	cpuCautionPct  = envFloat("XALGORIX_CPU_CAUTION_PCT", 70)
	cpuCriticalPct = envFloat("XALGORIX_CPU_CRITICAL_PCT", 90)

	// RAM: minimum free RAM in MB.
	// Auto-scaled in init() based on total system RAM.
	ramCautionMB  int64
	ramCriticalMB int64

	// Disk: minimum free disk in MB.
	diskCautionMB  = envInt64("XALGORIX_DISK_CAUTION_MB", 2048) // 2 GB
	diskCriticalMB = envInt64("XALGORIX_DISK_CRITICAL_MB", 1024) // 1 GB

	// Hard ceiling on concurrent instances regardless of resources.
	// Auto-scaled in init() based on CPU cores.
	maxInstances int

	// Per-process memory limit for heavy tools (bytes).
	// Auto-scaled in init() based on total RAM. Set to 0 to disable.
	HeavyToolMemLimitBytes int64
)

func init() {
	cores := runtime.NumCPU()
	totalMB, _ := readMemInfo()

	// ── Max concurrent scan instances ──
	// Formula: max(1, cores / 2), capped at 10.
	// 1-core  → 1 instance,  2-core → 1,  4-core → 2,  12-core → 6
	autoMax := cores / 2
	if autoMax < 1 {
		autoMax = 1
	}
	if autoMax > 10 {
		autoMax = 10
	}
	maxInstances = envInt("XALGORIX_MAX_INSTANCES", autoMax)

	// ── RAM thresholds ──
	// Caution: 25% of total RAM (4GB VPS → 1024MB, 24GB → 6144MB)
	// Critical: 12% of total RAM (4GB VPS → 512MB, 24GB → 2880MB)
	autoCaution := totalMB / 4
	if autoCaution < 512 {
		autoCaution = 512
	}
	autoCritical := totalMB * 12 / 100
	if autoCritical < 256 {
		autoCritical = 256
	}
	ramCautionMB = envInt64("XALGORIX_RAM_CAUTION_MB", autoCaution)
	ramCriticalMB = envInt64("XALGORIX_RAM_CRITICAL_MB", autoCritical)

	// ── Per-tool memory limit ──
	// Formula: 25% of total RAM, capped at 4GB.
	// 4GB VPS → 1024 MB per tool,  24GB → 4096 MB per tool (capped)
	autoMemLimit := totalMB / 4
	if autoMemLimit > 4096 {
		autoMemLimit = 4096
	}
	if autoMemLimit < 256 {
		autoMemLimit = 256
	}
	HeavyToolMemLimitBytes = envInt64("XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB", autoMemLimit) * 1024 * 1024

	log.Printf("[RESOURCES] Auto-scaled for %d cores, %d MB RAM: max_instances=%d, "+
		"ram_caution=%dMB, ram_critical=%dMB, tool_mem_limit=%dMB",
		cores, totalMB, maxInstances, ramCautionMB, ramCriticalMB,
		HeavyToolMemLimitBytes/(1024*1024))
}

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

// EffectiveMaxInstances computes the live concurrency ceiling based on
// current system resources. This dynamically shrinks below maxInstances
// when CPU or RAM is under pressure.
//
// Algorithm:
//   - Start from the static maxInstances ceiling
//   - At LevelCaution: halve the ceiling (min 1)
//   - At LevelCritical: drop to 1
//   - Also cap by available RAM: each instance gets ~500MB headroom
func EffectiveMaxInstances() (int, string) {
	stats := GetStats()
	level, reason := CurrentLevel()

	effective := maxInstances

	// ── RAM-based cap ──
	// Each running scan + its tools needs ~500MB headroom.
	// Reserve ramCriticalMB for the OS, divide the rest by 500.
	spare := stats.MemAvailableMB - ramCriticalMB
	if spare < 0 {
		spare = 0
	}
	ramCap := int(spare / 500)
	if ramCap < 1 {
		ramCap = 1
	}
	if ramCap < effective {
		effective = ramCap
	}

	// ── Pressure-based reduction ──
	switch level {
	case LevelCritical:
		effective = 1
	case LevelCaution:
		effective = effective / 2
		if effective < 1 {
			effective = 1
		}
	}

	return effective, reason
}

// CanAdmitScan decides whether a new scan instance should be started.
// Layer 1: admission control. Uses EffectiveMaxInstances for a live,
// resource-aware concurrency ceiling instead of a fixed number.
func CanAdmitScan(runningCount int) (bool, string) {
	effMax, reason := EffectiveMaxInstances()

	if runningCount >= effMax {
		return false, fmt.Sprintf("dynamic limit: %d/%d instances (ceiling=%d, %s)",
			runningCount, effMax, maxInstances, reason)
	}

	return true, fmt.Sprintf("%d/%d instances — %s", runningCount, effMax, reason)
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

// MaxInstances returns the configured hard ceiling (static, set at init).
func MaxInstances() int {
	return maxInstances
}

// LiveMaxInstances returns the current effective ceiling (dynamic, based on live resources).
func LiveMaxInstances() int {
	n, _ := EffectiveMaxInstances()
	return n
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
