package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// saveQueueState saves the current queue state to disk.
func (s *Server) saveQueueState(idx int, req ScanRequest, progress ...queueProgress) {
	normalizeScanRequestActivity(&req)
	state := QueueState{
		InstanceID:     req.InstanceID,
		Targets:        req.Targets,
		CurrentIdx:     idx,
		Instruction:    req.Instruction,
		ScanMode:       req.ScanMode,
		StartedAt:      time.Now().Format(time.RFC3339),
		Active:         true,
		Name:           req.Name,
		SeverityFilter: req.SeverityFilter,
		Phases:         req.Phases,
		ReconMode:      req.ReconMode,
		ScanIntensity:  req.ScanIntensity,
		CompanyName:    req.CompanyName,
		LogoPath:       req.LogoPath,
		DiscordWebhook: req.DiscordWebhook,
	}
	if len(progress) > 0 {
		p := progress[0]
		state.ActiveTarget = p.ActiveTarget
		state.ActiveScanDir = p.ActiveScanDir
		state.ActiveScanID = p.ActiveScanID
		state.WildcardActiveTarget = p.WildcardActiveTarget
		state.WildcardActiveScanDir = p.WildcardActiveScanDir
		state.WildcardActiveScanID = p.WildcardActiveScanID
		state.WildcardDiscoveryDone = p.WildcardDiscoveryDone
		state.WildcardSubdomains = append([]string(nil), p.WildcardSubdomains...)
		state.WildcardSubIndex = p.WildcardSubIndex
	} else if req.ResumeScanDir != "" || len(req.ResumeSubdomains) > 0 {
		state.ActiveTarget = req.ResumeActiveTarget
		state.ActiveScanDir = req.ResumeScanDir
		state.ActiveScanID = req.ResumeScanID
		state.WildcardActiveTarget = req.ResumeSubScanTarget
		state.WildcardActiveScanDir = req.ResumeSubScanDir
		state.WildcardActiveScanID = req.ResumeSubScanID
		state.WildcardDiscoveryDone = req.ResumeDiscoveryDone
		state.WildcardSubdomains = append([]string(nil), req.ResumeSubdomains...)
		state.WildcardSubIndex = req.ResumeSubIndex
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal queue state: %v", err)
		return
	}
	path := s.queueStatePathForInstance(req.InstanceID)
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Printf("Error: failed to save queue state: %v", err)
	}
}

func (s *Server) queueStatePath() string {
	return filepath.Join(s.dataDir, "queue_state.json")
}

func (s *Server) queueStatePathForInstance(instanceID string) string {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return s.queueStatePath()
	}
	return filepath.Join(s.dataDir, fmt.Sprintf("queue_state_%s.json", sanitizeQueueStateID(instanceID)))
}

func sanitizeQueueStateID(instanceID string) string {
	clean := sanitizeTarget(instanceID)
	if clean == "" {
		return "unknown"
	}
	return clean
}

type queueStateEntry struct {
	state   *QueueState
	path    string
	modTime time.Time
}

func (s *Server) queueStatePaths() []string {
	var paths []string
	legacy := s.queueStatePath()
	if _, err := os.Stat(legacy); err == nil {
		paths = append(paths, legacy)
	}
	matches, _ := filepath.Glob(filepath.Join(s.dataDir, "queue_state_*.json"))
	paths = append(paths, matches...)
	sort.Strings(paths)
	return compactStrings(paths)
}

func compactStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := values[:0]
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func queueStateInstanceIDFromPath(path string) string {
	base := filepath.Base(path)
	if base == "queue_state.json" {
		return ""
	}
	if !strings.HasPrefix(base, "queue_state_") || !strings.HasSuffix(base, ".json") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(base, "queue_state_"), ".json")
}

func (s *Server) loadQueueStateEntry(path string) (queueStateEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return queueStateEntry{}, err
	}
	var state QueueState
	if err := json.Unmarshal(data, &state); err != nil {
		return queueStateEntry{}, err
	}
	if state.InstanceID == "" {
		state.InstanceID = queueStateInstanceIDFromPath(path)
	}
	info, _ := os.Stat(path)
	modTime := time.Time{}
	if info != nil {
		modTime = info.ModTime()
	}
	return queueStateEntry{state: &state, path: path, modTime: modTime}, nil
}

// loadQueueState loads queue state from disk if exists
func (s *Server) loadQueueState() *QueueState {
	entries := s.validQueueStateEntries(false)
	if len(entries) == 0 {
		return nil
	}
	return entries[0].state
}

func (s *Server) validQueueStateEntries(clearInvalid bool) []queueStateEntry {
	paths := s.queueStatePaths()
	if len(paths) == 0 {
		return nil
	}
	var valid []queueStateEntry
	for _, path := range paths {
		entry, err := s.loadQueueStateEntry(path)
		if err != nil {
			if clearInvalid {
				log.Printf("[queue] Invalid queue state %s, clearing: %v", path, err)
				s.clearQueueStatePath(path)
			}
			continue
		}
		if reason := invalidQueueStateReason(entry.state); reason != "" {
			if clearInvalid && reason != "inactive" {
				log.Printf("[queue] Invalid queue state %s (%s), clearing.", path, reason)
				s.clearQueueStatePath(path)
			}
			continue
		}
		valid = append(valid, entry)
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if !valid[i].modTime.Equal(valid[j].modTime) {
			return valid[i].modTime.After(valid[j].modTime)
		}
		return valid[i].state.StartedAt > valid[j].state.StartedAt
	})
	return valid
}

func invalidQueueStateReason(state *QueueState) string {
	if state == nil || !state.Active {
		return "inactive"
	}
	if len(state.Targets) == 0 {
		return "empty"
	}
	if state.CurrentIdx < 0 {
		return "corrupt_index"
	}
	if state.CurrentIdx >= len(state.Targets) {
		return "completed"
	}
	return ""
}

func scanRequestFromQueueState(state *QueueState, sourcePath string) ScanRequest {
	if state == nil {
		return ScanRequest{}
	}
	currentIdx := clampInt(state.CurrentIdx, 0, len(state.Targets))
	return ScanRequest{
		Targets:              append([]string(nil), state.Targets[currentIdx:]...),
		Instruction:          state.Instruction,
		ScanMode:             state.ScanMode,
		IsResume:             true,
		ResumeQueueStatePath: sourcePath,
		Name:                 state.Name,
		SeverityFilter:       append([]string(nil), state.SeverityFilter...),
		Phases:               append([]int(nil), state.Phases...),
		ReconMode:            state.ReconMode,
		ScanIntensity:        state.ScanIntensity,
		CompanyName:          state.CompanyName,
		LogoPath:             state.LogoPath,
		DiscordWebhook:       state.DiscordWebhook,
		ResumeActiveTarget:   state.ActiveTarget,
		ResumeScanDir:        state.ActiveScanDir,
		ResumeScanID:         state.ActiveScanID,
		ResumeSubScanTarget:  state.WildcardActiveTarget,
		ResumeSubScanDir:     state.WildcardActiveScanDir,
		ResumeSubScanID:      state.WildcardActiveScanID,
		ResumeSubdomains:     append([]string(nil), state.WildcardSubdomains...),
		ResumeSubIndex:       state.WildcardSubIndex,
		ResumeDiscoveryDone:  state.WildcardDiscoveryDone,
		ResumeOriginalTarget: state.CurrentIdx,
	}
}

func autoResumeQueueEntries(entries []queueStateEntry) []queueStateEntry {
	out := entries[:0]
	for _, entry := range entries {
		if entry.state != nil && entry.state.Paused {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func splitInstanceTargets(targets string) []string {
	var out []string
	for _, part := range strings.Split(targets, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func fillResumeRequestDefaults(req *ScanRequest, defaults ScanRequest) {
	if req == nil {
		return
	}
	if len(req.Targets) == 0 {
		req.Targets = append([]string(nil), defaults.Targets...)
	}
	if req.Instruction == "" {
		req.Instruction = defaults.Instruction
	}
	if req.ScanMode == "" {
		req.ScanMode = defaults.ScanMode
	}
	if req.Name == "" {
		req.Name = defaults.Name
	}
	if len(req.SeverityFilter) == 0 {
		req.SeverityFilter = append([]string(nil), defaults.SeverityFilter...)
	}
	if len(req.Phases) == 0 {
		req.Phases = append([]int(nil), defaults.Phases...)
	}
	if req.ReconMode == "" {
		req.ReconMode = defaults.ReconMode
	}
	if req.ScanIntensity == "" {
		req.ScanIntensity = defaults.ScanIntensity
	}
	if req.CompanyName == "" {
		req.CompanyName = defaults.CompanyName
	}
	if req.LogoPath == "" {
		req.LogoPath = defaults.LogoPath
	}
	if req.DiscordWebhook == "" {
		req.DiscordWebhook = defaults.DiscordWebhook
	}
}

func (s *Server) scanRequestForPausedInstance(instanceID string, inst *ScanInstance) (ScanRequest, bool, string) {
	if inst == nil {
		return ScanRequest{}, false, "instance not found"
	}

	inst.mu.RLock()
	defaultReq := ScanRequest{
		Targets:        splitInstanceTargets(inst.Targets),
		Instruction:    inst.Instruction,
		ScanMode:       inst.ScanMode,
		SeverityFilter: append([]string(nil), inst.SeverityFilter...),
		DiscordWebhook: inst.DiscordWebhook,
		Name:           inst.Name,
		Phases:         append([]int(nil), inst.Phases...),
		ReconMode:      inst.ReconMode,
		ScanIntensity:  inst.ScanIntensity,
		CompanyName:    inst.CompanyName,
		LogoPath:       inst.LogoPath,
		IsResume:       true,
	}
	scanDir := inst.scanDir
	inst.mu.RUnlock()

	queuePath := s.queueStatePathForInstance(instanceID)
	if entry, err := s.loadQueueStateEntry(queuePath); err == nil {
		if reason := invalidQueueStateReason(entry.state); reason == "" {
			req := scanRequestFromQueueState(entry.state, entry.path)
			fillResumeRequestDefaults(&req, defaultReq)
			req.IsResume = true
			return req, true, ""
		}
	}

	if scanDir == "" {
		return ScanRequest{}, false, "no persisted scan state found"
	}
	if strings.EqualFold(defaultReq.ScanMode, "wildcard") {
		return ScanRequest{}, false, "wildcard resume requires saved queue state"
	}

	defaultReq.ResumeScanDir = scanDir
	defaultReq.ResumeScanID = filepath.Base(scanDir)
	if rec, ok := loadScanRecordFromDir(scanDir); ok && rec.Target != "" {
		defaultReq.ResumeActiveTarget = rec.Target
	} else if len(defaultReq.Targets) > 0 {
		defaultReq.ResumeActiveTarget = defaultReq.Targets[0]
	}
	return defaultReq, true, ""
}

func shouldPreserveQueueStateOnExit(status, stopReason string, panicRecovered bool) bool {
	if panicRecovered {
		return true
	}
	if status == "paused" || stopReason == "user_paused" {
		return true
	}
	return strings.HasPrefix(stopReason, "signal_")
}

func shouldAdvanceQueueAfterTarget(stopRequested bool, status string) bool {
	if stopRequested {
		return false
	}
	switch status {
	case "paused", "stopped":
		return false
	default:
		return true
	}
}

func isInterruptedInstanceStatus(status string) bool {
	return status == "paused" || status == "stopped"
}

func (s *Server) instanceRunStatus(instanceID string) (string, string) {
	if instanceID == "" {
		return "", ""
	}
	s.instancesMu.RLock()
	inst := s.instances[instanceID]
	s.instancesMu.RUnlock()
	if inst == nil {
		return "", ""
	}
	inst.mu.RLock()
	status := inst.Status
	stopReason := inst.StopReason
	inst.mu.RUnlock()
	return status, stopReason
}

func (s *Server) instanceInterrupted(instanceID string) bool {
	status, _ := s.instanceRunStatus(instanceID)
	return isInterruptedInstanceStatus(status)
}

func (s *Server) markQueueStatePaused(instanceID string) {
	entry, err := s.loadQueueStateEntry(s.queueStatePathForInstance(instanceID))
	if err != nil || entry.state == nil {
		return
	}
	entry.state.Paused = true
	data, err := json.MarshalIndent(entry.state, "", "  ")
	if err != nil {
		log.Printf("Error: failed to marshal paused queue state: %v", err)
		return
	}
	if err := os.WriteFile(entry.path, data, 0600); err != nil {
		log.Printf("Error: failed to mark queue state paused: %v", err)
	}
}

// clearQueueState removes queue state. With an instance ID it clears only that
// scan's resume file; with no ID it clears every resumable queue.
func (s *Server) clearQueueState(instanceIDs ...string) {
	if len(instanceIDs) > 0 {
		for _, instanceID := range instanceIDs {
			if strings.TrimSpace(instanceID) == "" {
				s.clearQueueStatePath(s.queueStatePath())
				continue
			}
			s.clearQueueStatePath(s.queueStatePathForInstance(instanceID))
		}
		return
	}
	for _, path := range s.queueStatePaths() {
		s.clearQueueStatePath(path)
	}
}

func (s *Server) clearQueueStatePath(path string) {
	if path == "" {
		return
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Printf("Warning: failed to remove queue state file %s: %v", path, err)
	}
}
