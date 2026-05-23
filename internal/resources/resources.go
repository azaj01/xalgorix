// Package resources provides real-time system resource monitoring for
// dynamic scan admission control and runtime backpressure.
//
// It reads Linux /proc files (meminfo, loadavg) and uses syscall.Statfs
// for disk space. All thresholds are configurable via environment variables.
package resources

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
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
	ProcessRSSMB   int64
	GoHeapAllocMB  int64
	GoHeapSysMB    int64
	Goroutines     int
}

// CapacitySnapshot describes the current adaptive capacity model used by the
// scan scheduler and subprocess launcher.
type CapacitySnapshot struct {
	ActiveToolLeases      int
	ActiveHeavyToolLeases int
	HeavyToolSlots        int
	LightToolSlots        int
	ToolMemLimitMB        int64
	ScanMemoryBudgetMB    int64
	ScanCPULoad           float64
	HeavyToolCPULoad      float64
	GoMemoryLimitMB       int64
	Reason                string
}

// ToolLease represents reserved CPU/RAM headroom for one subprocess launch.
// Call Release exactly once after the process exits.
type ToolLease struct {
	id               uint64
	toolName         string
	heavy            bool
	memoryLimitBytes int64
	released         bool
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
	perScanCPULoad float64

	// Estimated load-average budget consumed by one heavy terminal tool.
	heavyToolCPULoad float64

	// Per-process memory limit for heavy tools (bytes).
	// Auto-scaled in init() based on total RAM. Set to 0 to disable.
	HeavyToolMemLimitBytes int64

	// Total RAM budget per running scan instance. This is the admission-control
	// unit used to decide how many scans can run concurrently.
	scanMemoryBudgetMB int64

	// Extra RAM budget per running scan for the Go process, browser state,
	// LLM history, buffers, and small helper tools around one heavy command.
	scanOverheadMB int64

	goMemoryLimitMB int64

	resourceMu            sync.Mutex
	nextLeaseID           uint64
	activeToolLeases      int
	activeHeavyToolLeases int
)

const (
	toolLeasePollInterval = 5 * time.Second
	toolLeaseLogInterval  = 30 * time.Second
)

func init() {
	cores := runtime.NumCPU()
	totalMB, _ := readMemInfo()

	perScanCPULoad = envFloatDefault("XALGORIX_SCAN_CPU_LOAD", autoScanCPULoad(cores))
	heavyToolCPULoad = envFloatDefault("XALGORIX_HEAVY_TOOL_CPU_LOAD", autoHeavyToolCPULoad(cores))
	scanOverheadMB = envInt64Default("XALGORIX_SCAN_OVERHEAD_MB", autoScanOverheadMB(totalMB))
	scanMemoryBudgetMB = envInt64Default("XALGORIX_SCAN_MEMORY_BUDGET_MB", autoScanMemoryBudgetMB(totalMB, cores))

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
	toolMemLimitMB := autoHeavyToolMemLimitMB(totalMB)
	if override, ok := envOptionalInt64("XALGORIX_HEAVY_TOOL_MEM_LIMIT_MB"); ok {
		toolMemLimitMB = override
	}
	HeavyToolMemLimitBytes = toolMemLimitMB * 1024 * 1024

	configureGoRuntimeLimits(totalMB)

	manualCap := "none"
	if manualMaxInstances > 0 {
		manualCap = strconv.Itoa(manualMaxInstances)
	}
	log.Printf("[RESOURCES] Auto-scaled for %d cores, %d MB RAM: manual_instance_cap=%s, "+
		"ram_caution=%dMB, ram_critical=%dMB, tool_mem_limit=%dMB, scan_budget=%dMB, "+
		"scan_cpu_budget=%.2f, heavy_tool_cpu_budget=%.2f, go_mem_limit=%dMB",
		cores, totalMB, manualCap, ramCautionMB, ramCriticalMB,
		HeavyToolMemLimitBytes/(1024*1024), perInstanceMemoryBudgetMB(),
		perScanCPULoad, heavyToolCPULoad, goMemoryLimitMB)
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
	stats.ProcessRSSMB = readProcessRSSMB()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	stats.GoHeapAllocMB = int64(mem.HeapAlloc / 1024 / 1024)
	stats.GoHeapSysMB = int64(mem.HeapSys / 1024 / 1024)
	stats.Goroutines = runtime.NumGoroutine()

	return stats
}

// CurrentLevel evaluates the system's overall resource pressure.
// Returns the worst (highest) level across all resource dimensions.
func CurrentLevel() (Level, string) {
	stats := GetStats()
	return currentLevelForStats(stats)
}

func currentLevelForStats(stats SystemStats) (Level, string) {
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

	detail := fmt.Sprintf("%s; dynamic slots: cpu=%d, ram=%d, scan_budget=%dMB, scan_cpu_budget=%.2f",
		reason, cpuCap, ramCap, perInstanceMemoryBudgetMB(), perScanCPULoad)
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

func autoScanCPULoad(cores int) float64 {
	if cores <= 1 {
		return 0.85
	}
	if cores == 2 {
		return 0.80
	}
	return 0.75
}

func autoHeavyToolCPULoad(cores int) float64 {
	if cores <= 1 {
		return 0.85
	}
	if cores == 2 {
		return 0.90
	}
	return 1.0
}

func autoScanOverheadMB(totalMB int64) int64 {
	overhead := totalMB / 16
	if overhead < 256 {
		overhead = 256
	}
	if overhead > 512 {
		overhead = 512
	}
	return overhead
}

func autoScanMemoryBudgetMB(totalMB int64, cores int) int64 {
	if totalMB <= 0 {
		return 1024
	}
	targetSlots := cores
	if targetSlots < 1 {
		targetSlots = 1
	}
	if targetSlots > 6 {
		targetSlots = 6
	}
	usable := totalMB - hostReserveMB(totalMB)
	if usable < 1024 {
		usable = 1024
	}
	budget := usable / int64(targetSlots)
	if budget < 768 {
		budget = 768
	}
	if budget > 2048 {
		budget = 2048
	}
	return budget
}

func autoGoMemoryLimitMB(totalMB int64) int64 {
	if totalMB <= 0 {
		return 0
	}
	limit := totalMB * 45 / 100
	if limit < 512 {
		limit = 512
	}
	maxLimit := totalMB - hostReserveMB(totalMB)
	if maxLimit > 0 && limit > maxLimit {
		limit = maxLimit
	}
	if limit > 4096 {
		limit = 4096
	}
	return limit
}

func hostReserveMB(totalMB int64) int64 {
	reserve := totalMB * 20 / 100
	if reserve < 512 {
		reserve = 512
	}
	if reserve > 2048 {
		reserve = 2048
	}
	return reserve
}

func configureGoRuntimeLimits(totalMB int64) {
	override, hasOverride := envOptionalInt64("XALGORIX_GO_MEM_LIMIT_MB")
	if !hasOverride {
		if _, hasGoMemLimit := os.LookupEnv("GOMEMLIMIT"); hasGoMemLimit {
			log.Printf("[RESOURCES] GOMEMLIMIT is already set; leaving Go runtime memory limit unchanged")
			return
		}
		override = autoGoMemoryLimitMB(totalMB)
	}
	if override > 0 {
		debug.SetMemoryLimit(override * 1024 * 1024)
		goMemoryLimitMB = override
	}
	if _, hasGOGC := os.LookupEnv("GOGC"); !hasGOGC {
		if totalMB > 0 && totalMB <= 4096 {
			debug.SetGCPercent(75)
		} else {
			debug.SetGCPercent(100)
		}
	}
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
// Layer 2: pre-exec throttle. The decision uses both live pressure and active
// tool leases, so CPU-heavy commands cannot stampede when a scan fleet starts.
func CanExecTool(isHeavy bool) (bool, string) {
	stats := GetStats()
	level, reason := currentLevelForStats(stats)
	resourceMu.Lock()
	activeTotal := activeToolLeases
	activeHeavy := activeHeavyToolLeases
	resourceMu.Unlock()
	capacity := toolCapacityForStats(stats, level, reason, activeTotal, activeHeavy)
	return toolSlotAdmission(isHeavy, capacity, activeTotal, activeHeavy)
}

// AcquireToolLease reserves live CPU/RAM headroom for one subprocess. The
// caller must release the lease after the process exits.
func AcquireToolLease(isHeavy bool, maxWait time.Duration, toolName string) (*ToolLease, bool) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if maxWait > 0 {
		ctx, cancel = context.WithTimeout(ctx, maxWait)
		defer cancel()
	}
	lease, err := acquireToolLeaseWithContext(ctx, isHeavy, toolName, toolLeasePollInterval)
	return lease, err == nil
}

// AcquireToolLeaseContext reserves live CPU/RAM headroom for one subprocess.
// Unlike the legacy maxWait API, this never refuses purely because the system
// stayed busy for a fixed number of seconds. It blocks until capacity is
// available or until the caller's context is cancelled.
func AcquireToolLeaseContext(ctx context.Context, isHeavy bool, toolName string) (*ToolLease, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return acquireToolLeaseWithContext(ctx, isHeavy, toolName, toolLeasePollInterval)
}

func acquireToolLeaseWithContext(ctx context.Context, isHeavy bool, toolName string, pollInterval time.Duration) (*ToolLease, error) {
	if pollInterval <= 0 {
		pollInterval = time.Second
	}
	toolLabel := ToolLogLabel(toolName)
	waited := false
	startedWaiting := time.Now()
	lastLog := startedWaiting
	var lastReason string

	for {
		lease, reason := tryAcquireToolLease(isHeavy, toolLabel)
		if lease != nil {
			if waited {
				log.Printf("[RESOURCES] Resources recovered; proceeding with %s", toolLabel)
			}
			return lease, nil
		}
		lastReason = reason

		if !waited {
			log.Printf("[THROTTLE] Queueing %s until resources recover — %s", toolLabel, reason)
			waited = true
			lastLog = time.Now()
		} else if time.Since(lastLog) >= toolLeaseLogInterval {
			log.Printf("[THROTTLE] Still waiting to exec %s after %s — %s",
				toolLabel, time.Since(startedWaiting).Round(time.Second), lastReason)
			lastLog = time.Now()
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("cancelled while waiting to launch %s after %s: %w (last resource state: %s)",
				toolLabel, time.Since(startedWaiting).Round(time.Second), ctx.Err(), lastReason)
		case <-time.After(pollInterval):
		}
	}
}

// ToolLogLabel returns a short, non-sensitive label for resource-manager logs.
// Callers may pass full shell commands; this intentionally logs only the tool
// name so URLs, tokens, headers, and payloads do not end up in journald.
func ToolLogLabel(toolName string) string {
	fields := strings.Fields(strings.TrimSpace(toolName))
	for i := 0; i < len(fields); i++ {
		part := strings.Trim(fields[i], `"'`)
		if part == "" {
			continue
		}
		if strings.Contains(part, "=") && !strings.Contains(part, "/") && !strings.HasPrefix(part, "-") {
			continue
		}
		switch part {
		case "sudo", "env", "command", "time", "timeout", "nice", "nohup":
			continue
		case "bash", "sh", "zsh":
			return "shell"
		}
		if slash := strings.LastIndex(part, "/"); slash >= 0 {
			part = part[slash+1:]
		}
		if part == "" {
			continue
		}
		for _, r := range part {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' || r == '+' {
				continue
			}
			return "tool"
		}
		return part
	}
	return "tool"
}

func tryAcquireToolLease(isHeavy bool, toolLabel string) (*ToolLease, string) {
	stats := GetStats()
	level, levelReason := currentLevelForStats(stats)

	resourceMu.Lock()
	defer resourceMu.Unlock()

	capacity := toolCapacityForStats(stats, level, levelReason, activeToolLeases, activeHeavyToolLeases)
	if ok, reason := toolSlotAdmission(isHeavy, capacity, activeToolLeases, activeHeavyToolLeases); !ok {
		return nil, reason
	}

	projectedTotal := activeToolLeases + 1
	projectedHeavy := activeHeavyToolLeases
	if isHeavy {
		projectedHeavy++
	}
	limitMB := toolMemoryLimitMBForStats(stats, isHeavy, projectedTotal, projectedHeavy, level)
	if isHeavy && HeavyToolMemLimitBytes > 0 && limitMB < minimumHeavyToolMemMB() {
		return nil, fmt.Sprintf("not enough RAM for heavy tool: dynamic limit %dMB below minimum %dMB (%s)",
			limitMB, minimumHeavyToolMemMB(), capacity.Reason)
	}

	nextLeaseID++
	activeToolLeases++
	if isHeavy {
		activeHeavyToolLeases++
	}
	lease := &ToolLease{
		id:               nextLeaseID,
		toolName:         toolLabel,
		heavy:            isHeavy,
		memoryLimitBytes: limitMB * 1024 * 1024,
	}
	log.Printf("[RESOURCES] Lease %d acquired for %s: heavy=%v active_tools=%d active_heavy=%d mem_limit=%dMB slots=%d/%d",
		lease.id, toolLabel, isHeavy, activeToolLeases, activeHeavyToolLeases, limitMB,
		capacity.HeavyToolSlots, capacity.LightToolSlots)
	return lease, capacity.Reason
}

func toolSlotAdmission(isHeavy bool, capacity toolCapacity, activeTotal, activeHeavy int) (bool, string) {
	if isHeavy && activeHeavy >= capacity.HeavyToolSlots {
		return false, fmt.Sprintf("heavy tool slots full: %d/%d (%s)",
			activeHeavy, capacity.HeavyToolSlots, capacity.Reason)
	}
	if activeTotal >= capacity.LightToolSlots {
		return false, fmt.Sprintf("tool slots full: %d/%d (%s)",
			activeTotal, capacity.LightToolSlots, capacity.Reason)
	}
	return true, capacity.Reason
}

// Release frees the CPU/RAM reservation held by this tool lease.
func (l *ToolLease) Release() {
	if l == nil {
		return
	}
	resourceMu.Lock()
	defer resourceMu.Unlock()
	if l.released {
		return
	}
	l.released = true
	if activeToolLeases > 0 {
		activeToolLeases--
	}
	if l.heavy && activeHeavyToolLeases > 0 {
		activeHeavyToolLeases--
	}
	log.Printf("[RESOURCES] Lease %d released for %s: active_tools=%d active_heavy=%d",
		l.id, l.toolName, activeToolLeases, activeHeavyToolLeases)
}

// MemoryLimitBytes returns the per-process memory ceiling selected for this
// lease. A zero value means memory limiting is disabled by configuration.
func (l *ToolLease) MemoryLimitBytes() int64 {
	if l == nil {
		return CurrentToolMemoryLimitBytes(true)
	}
	return l.memoryLimitBytes
}

// CurrentToolMemoryLimitBytes returns a best-effort memory limit for callers
// that cannot hold an explicit lease.
func CurrentToolMemoryLimitBytes(isHeavy bool) int64 {
	stats := GetStats()
	level, _ := currentLevelForStats(stats)
	resourceMu.Lock()
	projectedTotal := activeToolLeases + 1
	projectedHeavy := activeHeavyToolLeases
	if isHeavy {
		projectedHeavy++
	}
	resourceMu.Unlock()
	return toolMemoryLimitMBForStats(stats, isHeavy, projectedTotal, projectedHeavy, level) * 1024 * 1024
}

// Capacity returns the current resource model, including active tool leases.
func Capacity() CapacitySnapshot {
	stats := GetStats()
	level, reason := currentLevelForStats(stats)
	resourceMu.Lock()
	activeTotal := activeToolLeases
	activeHeavy := activeHeavyToolLeases
	resourceMu.Unlock()
	capacity := toolCapacityForStats(stats, level, reason, activeTotal, activeHeavy)
	return CapacitySnapshot{
		ActiveToolLeases:      activeTotal,
		ActiveHeavyToolLeases: activeHeavy,
		HeavyToolSlots:        capacity.HeavyToolSlots,
		LightToolSlots:        capacity.LightToolSlots,
		ToolMemLimitMB:        toolMemoryLimitMBForStats(stats, true, activeTotal+1, activeHeavy+1, level),
		ScanMemoryBudgetMB:    perInstanceMemoryBudgetMB(),
		ScanCPULoad:           perScanCPULoad,
		HeavyToolCPULoad:      heavyToolCPULoad,
		GoMemoryLimitMB:       goMemoryLimitMB,
		Reason:                capacity.Reason,
	}
}

type toolCapacity struct {
	HeavyToolSlots int
	LightToolSlots int
	Reason         string
}

func toolCapacityForStats(stats SystemStats, level Level, reason string, activeTotal, activeHeavy int) toolCapacity {
	spareMB := stats.MemAvailableMB - ramCriticalMB
	if level >= LevelCritical {
		lightSlots := criticalLightToolSlots(stats)
		detail := fmt.Sprintf("%s; pressure_mode=true, tool_slots: heavy=%d/%d light=%d/%d, active_tools=%d, active_heavy=%d",
			reason, activeHeavy, 0, activeTotal, lightSlots, activeTotal, activeHeavy)
		return toolCapacity{HeavyToolSlots: 0, LightToolSlots: lightSlots, Reason: detail}
	}
	if spareMB <= 0 {
		return toolCapacity{Reason: reason}
	}

	memUnitMB := HeavyToolMemLimitBytes / (1024 * 1024)
	if memUnitMB <= 0 {
		memUnitMB = autoHeavyToolMemLimitMB(stats.MemTotalMB)
	}
	if memUnitMB < minimumHeavyToolMemMB() {
		memUnitMB = minimumHeavyToolMemMB()
	}
	memSlots := int(spareMB / memUnitMB)
	if memSlots < 1 && spareMB >= minimumHeavyToolMemMB() {
		memSlots = 1
	}

	cpuHeavySlots := heavyToolCPUCapacity(stats)
	parallelCap := heavyToolParallelCap(stats.CPUCores)
	heavySlots := minInt(memSlots, minInt(cpuHeavySlots, parallelCap))
	if level == LevelCaution && heavySlots > 1 {
		heavySlots = 1
	}

	lightMemSlots := int(spareMB / 128)
	if lightMemSlots < 1 && spareMB >= 128 {
		lightMemSlots = 1
	}
	lightSlots := minInt(lightMemSlots, lightToolCPUCapacity(stats))
	if lightSlots < heavySlots {
		lightSlots = heavySlots
	}
	if level == LevelCaution && lightSlots > maxInt(1, stats.CPUCores) {
		lightSlots = maxInt(1, stats.CPUCores)
	}

	detail := fmt.Sprintf("%s; tool_slots: heavy=%d/%d light=%d/%d, active_tools=%d, active_heavy=%d, mem_unit=%dMB, cpu_budget=%.2f",
		reason, activeHeavy, heavySlots, activeTotal, lightSlots, activeTotal, activeHeavy, memUnitMB, heavyToolCPULoad)
	return toolCapacity{HeavyToolSlots: heavySlots, LightToolSlots: lightSlots, Reason: detail}
}

func criticalLightToolSlots(stats SystemStats) int {
	if stats.MemAvailableMB < 128 {
		return 0
	}
	// Keep one low-footprint command moving under pressure so quality does not
	// collapse just because loadavg lags behind a finished tool. Heavy commands
	// remain blocked until normal headroom returns.
	return 1
}

func toolMemoryLimitMBForStats(stats SystemStats, isHeavy bool, projectedTotal, projectedHeavy int, level Level) int64 {
	if HeavyToolMemLimitBytes <= 0 {
		return 0
	}
	maxLimitMB := HeavyToolMemLimitBytes / (1024 * 1024)
	if maxLimitMB <= 0 {
		return 0
	}
	spareMB := stats.MemAvailableMB - ramCriticalMB
	if spareMB <= 0 {
		return minimumHeavyToolMemMB()
	}

	divisor := projectedHeavy
	if !isHeavy {
		divisor = projectedTotal
	}
	if divisor < 1 {
		divisor = 1
	}
	dynamicLimit := spareMB / int64(divisor)
	if level == LevelCaution {
		dynamicLimit = dynamicLimit * 3 / 4
	}
	if dynamicLimit > maxLimitMB {
		dynamicLimit = maxLimitMB
	}
	minLimit := minimumHeavyToolMemMB()
	if !isHeavy {
		minLimit = 128
	}
	if dynamicLimit < minLimit {
		dynamicLimit = minLimit
	}
	return dynamicLimit
}

func heavyToolCPUCapacity(stats SystemStats) int {
	budget := heavyToolCPULoad
	if budget <= 0 {
		budget = autoHeavyToolCPULoad(stats.CPUCores)
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

func lightToolCPUCapacity(stats SystemStats) int {
	criticalLoad := float64(stats.CPUCores) * cpuCriticalPct / 100
	headroom := criticalLoad - stats.LoadAvg1m
	if headroom <= 0 {
		return 0
	}
	capacity := int(headroom / 0.25)
	if capacity < 1 {
		return 1
	}
	cap := maxInt(2, stats.CPUCores*4)
	if capacity > cap {
		return cap
	}
	return capacity
}

func heavyToolParallelCap(cores int) int {
	if cores <= 1 {
		return 1
	}
	if cores == 2 {
		return 2
	}
	return maxInt(2, cores-1)
}

func minimumHeavyToolMemMB() int64 {
	return 256
}

// WaitForResources blocks until resources are available, or until maxWait is
// exceeded. It keeps the old API for non-lease callers by acquiring and
// immediately releasing a short lease.
func WaitForResources(isHeavy bool, maxWait time.Duration, toolName string) bool {
	lease, ok := AcquireToolLease(isHeavy, maxWait, toolName)
	if lease != nil {
		lease.Release()
	}
	return ok
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

func readProcessRSSMB() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb / 1024
	}
	return 0
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

func envFloatDefault(key string, defaultVal float64) float64 {
	return envFloat(key, defaultVal)
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

func envInt64Default(key string, defaultVal int64) int64 {
	return envInt64(key, defaultVal)
}

func envOptionalInt64(key string) (int64, bool) {
	s, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(s) == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v < 0 {
		log.Printf("[RESOURCES] Invalid %s=%q, ignoring override", key, s)
		return 0, false
	}
	return v, true
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
