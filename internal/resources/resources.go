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
	diskCautionMB  = envInt64("XALGORIX_DISK_CAUTION_MB", 2048)  // 2 GB
	diskCriticalMB = envInt64("XALGORIX_DISK_CRITICAL_MB", 1024) // 1 GB

	// Optional manual ceiling on concurrent instances. By default there is no
	// static instance limit; live CPU/RAM headroom computes the ceiling.
	manualMaxInstances = envOptionalInt("XALGORIX_MAX_INSTANCES")

	// Estimated load-average budget consumed by one active scan instance.
	perScanCPULoad = envFloat("XALGORIX_SCAN_CPU_LOAD", 1.0)

	// Per-process memory limit for heavy tools (bytes).
	// Auto-scaled in init() based on total RAM. Set to 0 to disable.
	HeavyToolMemLimitBytes int64

	// Total RAM budget per running scan instance. This is the admission-control
	// unit used to decide how many scans can run concurrently.
	scanMemoryBudgetMB = envInt64("XALGORIX_SCAN_MEMORY_BUDGET_MB", 1024)

	// Extra RAM budget per running scan for the Go process, browser state,
	// LLM history, buffers, and small helper tools around one heavy command.
	scanOverheadMB = envInt64("XALGORIX_SCAN_OVERHEAD_MB", 384)
)

func init() {
	cores := runtime.NumCPU()
	totalMB, _ := readMemInfo()

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

	if scanMemoryBudgetMB < 1024 {
		log.Printf("[RESOURCES] XALGORIX_SCAN_MEMORY_BUDGET_MB=%d too low, using 1024", scanMemoryBudgetMB)
		scanMemoryBudgetMB = 1024
	}
	if scanOverheadMB < 128 {
		log.Printf("[RESOURCES] XALGORIX_SCAN_OVERHEAD_MB=%d too low, using 128", scanOverheadMB)
		scanOverheadMB = 128
	}

	// ── Per-tool memory limit ──
	// Default: fit one heavy tool inside the per-instance scan budget, leaving
	// scanOverheadMB for the agent, browser, buffers, and helper processes.
	HeavyToolMemLimitBytes = envInt64("XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB", autoHeavyToolMemLimitMB(totalMB)) * 1024 * 1024

	manualCap := "none"
	if manualMaxInstances > 0 {
		manualCap = strconv.Itoa(manualMaxInstances)
	}
	log.Printf("[RESOURCES] Auto-scaled for %d cores, %d MB RAM: manual_instance_cap=%s, "+
		"ram_caution=%dMB, ram_critical=%dMB, tool_mem_limit=%dMB, scan_budget=%dMB, cpu_budget=%.1f",
		cores, totalMB, manualCap, ramCautionMB, ramCriticalMB,
		HeavyToolMemLimitBytes/(1024*1024), perInstanceMemoryBudgetMB(), perScanCPULoad)
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

// EffectiveMaxInstances computes the live concurrency ceiling from current CPU,
// RAM, and disk pressure. There is no static default instance cap; if
// XALGORIX_MAX_INSTANCES is set, it is treated as an optional manual override.
//
// Algorithm:
//   - Compute CPU slots from remaining load-average headroom
//   - Compute RAM slots from available RAM and per-instance memory budget
//   - At LevelCaution: halve the dynamic ceiling
//   - At LevelCritical: admit no new scans until pressure recovers
//   - Apply XALGORIX_MAX_INSTANCES only when explicitly configured
func EffectiveMaxInstances() (int, string) {
	stats := GetStats()
	level, reason := CurrentLevel()
	return effectiveMaxInstancesForStats(stats, level, reason)
}

func effectiveMaxInstancesForStats(stats SystemStats, level Level, reason string) (int, string) {
	ramCap := memoryInstanceCapacity(stats)
	cpuCap := cpuInstanceCapacity(stats)
	effective := minInt(ramCap, cpuCap)

	switch level {
	case LevelCritical:
		effective = 0
	case LevelCaution:
		effective = effective / 2
		if effective == 0 && ramCap > 0 && cpuCap > 0 {
			effective = 1
		}
	}

	if manualMaxInstances > 0 && effective > manualMaxInstances {
		effective = manualMaxInstances
	}

	detail := fmt.Sprintf("%s; dynamic slots: cpu=%d, ram=%d, scan_budget=%dMB",
		reason, cpuCap, ramCap, perInstanceMemoryBudgetMB())
	if manualMaxInstances > 0 {
		detail += fmt.Sprintf(", manual_cap=%d", manualMaxInstances)
	}
	return effective, detail
}

func memoryInstanceCapacity(stats SystemStats) int {
	spare := stats.MemAvailableMB - ramCriticalMB
	if spare <= 0 {
		return 0
	}
	ramCap := int(spare / perInstanceMemoryBudgetMB())
	if ramCap < 1 {
		return 1
	}
	return ramCap
}

func cpuInstanceCapacity(stats SystemStats) int {
	budget := perScanCPULoad
	if budget <= 0 {
		budget = 1
	}
	criticalLoad := float64(stats.CPUCores) * cpuCriticalPct / 100
	headroom := criticalLoad - stats.LoadAvg1m
	if headroom <= 0 {
		return 0
	}
	capacity := int(headroom / budget)
	if capacity < 1 {
		return 1
	}
	return capacity
}

func perInstanceMemoryBudgetMB() int64 {
	toolLimitMB := HeavyToolMemLimitBytes / (1024 * 1024)
	budget := scanMemoryBudgetMB
	minBudget := toolLimitMB + scanOverheadMB
	if minBudget > budget {
		budget = minBudget
	}
	if budget < 1024 {
		return 1024
	}
	return budget
}

func autoHeavyToolMemLimitMB(totalMB int64) int64 {
	// Base limit scales with host memory but is capped. The scan-budget cap
	// below is what keeps the default admission model around 2GB per instance.
	limit := totalMB / 4
	if limit > 4096 {
		limit = 4096
	}
	if limit < 256 {
		limit = 256
	}

	budgetedLimit := scanMemoryBudgetMB - scanOverheadMB
	if budgetedLimit >= 256 && limit > budgetedLimit {
		limit = budgetedLimit
	}
	return limit
}

// CanAdmitScan decides whether a new scan instance should be started.
// Layer 1: admission control. Uses EffectiveMaxInstances for a live,
// resource-aware concurrency ceiling instead of a fixed number.
func CanAdmitScan(runningCount int) (bool, string) {
	effMax, reason := EffectiveMaxInstances()

	if effMax <= 0 {
		return false, fmt.Sprintf("dynamic limit: resources unavailable (%s)", reason)
	}

	if runningCount >= effMax {
		return false, fmt.Sprintf("dynamic limit: %d/%d instances (%s)",
			runningCount, effMax, reason)
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

// MaxInstances returns the optional manual cap. A zero value means no static
// cap is configured and the live resource ceiling is used directly.
func MaxInstances() int {
	return manualMaxInstances
}

// LiveMaxInstances returns the current effective ceiling (dynamic, based on live resources).
func LiveMaxInstances() int {
	n, _ := EffectiveMaxInstances()
	return n
}

// ProtectCurrentProcess lowers the OOM-killer score for the xalgorix parent
// process. Child scan tools are assigned a higher score when they launch, so
// under memory pressure the kernel should kill a tool before the web service.
func ProtectCurrentProcess() {
	if runtime.GOOS != "linux" {
		return
	}
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("-500"), 0644); err != nil {
		if !os.IsPermission(err) {
			log.Printf("[RESOURCES] Cannot protect xalgorix from OOM killer: %v", err)
		}
		return
	}
	log.Printf("[RESOURCES] xalgorix OOM score set to -500")
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

func envOptionalInt(key string) int {
	s, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(s) == "" {
		return 0
	}
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || v < 1 {
		log.Printf("[RESOURCES] Invalid %s=%q, ignoring manual cap", key, s)
		return 0
	}
	return v
}

// max returns the larger of two Levels.
func maxLevel(a, b Level) Level {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
