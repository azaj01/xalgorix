package web

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/safe"
)

type ScanSchedule struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Interval       string    `json:"interval"` // "hourly", "daily", "weekly", "monthly"
	NextRun        time.Time `json:"next_run"`
	LastRun        time.Time `json:"last_run,omitempty"`
	Enabled        bool      `json:"enabled"`
	Targets        []string  `json:"targets"`
	Instruction    string    `json:"instruction,omitempty"`
	ScanMode       string    `json:"scan_mode"`
	SeverityFilter []string  `json:"severity_filter,omitempty"`
	Phases         []int     `json:"phases,omitempty"`
	ReconMode      string    `json:"recon_mode,omitempty"`
	ScanIntensity  string    `json:"scan_intensity,omitempty"`
	CompanyName    string    `json:"company_name,omitempty"`
	LogoPath       string    `json:"logo_path,omitempty"`
	DiscordWebhook string    `json:"discord_webhook,omitempty"`
	Model          string    `json:"model,omitempty"`
}

func calculateNextRun(interval string, from time.Time) time.Time {
	switch strings.ToLower(interval) {
	case "hourly":
		return from.Add(time.Hour)
	case "daily":
		return from.AddDate(0, 0, 1)
	case "weekly":
		return from.AddDate(0, 0, 7)
	case "monthly":
		return from.AddDate(0, 1, 0)
	default:
		// Default fallback to 1 day
		return from.AddDate(0, 0, 1)
	}
}

// loadSchedulesFromDisk reads schedules directory and loads them into memory.
func (s *Server) loadSchedulesFromDisk() {
	dir := filepath.Join(s.dataDir, "_schedules")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("[SCHEDULER] Error creating schedules dir: %v", err)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("[SCHEDULER] Error reading schedules dir: %v", err)
		return
	}
	s.schedulesMu.Lock()
	defer s.schedulesMu.Unlock()
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[SCHEDULER] Error reading schedule file %s: %v", path, err)
			continue
		}
		var sch ScanSchedule
		if err := json.Unmarshal(data, &sch); err != nil {
			log.Printf("[SCHEDULER] Error decoding schedule %s: %v", path, err)
			continue
		}
		normalizeScheduleActivity(&sch)
		s.schedules[sch.ID] = &sch
	}
	log.Printf("[SCHEDULER] Loaded %d schedules from disk", len(s.schedules))
}

// saveScheduleToDisk writes a schedule to disk.
func (s *Server) saveScheduleToDisk(sch *ScanSchedule) error {
	dir := filepath.Join(s.dataDir, "_schedules")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	data, err := json.MarshalIndent(sch, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(dir, sch.ID+".json")
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath) // best-effort cleanup
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// deleteScheduleFromDisk deletes a schedule file.
func (s *Server) deleteScheduleFromDisk(id string) error {
	path := filepath.Join(s.dataDir, "_schedules", id+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// startScheduler runs the background checker loop.
func (s *Server) startScheduler() {
	// Evaluate overdue schedules immediately on startup so scans missed
	// while the server was down don't wait a full ticker interval.
	s.checkAndRunSchedules()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	log.Printf("[SCHEDULER] Started background scheduler ticker")
	for {
		select {
		case <-s.shutdownChan:
			log.Printf("[SCHEDULER] Stopping background scheduler")
			return
		case <-ticker.C:
			s.checkAndRunSchedules()
		}
	}
}

// checkAndRunSchedules evaluates all schedules and launches due scans.
func (s *Server) checkAndRunSchedules() {
	defer safe.Recover("scheduler.tick", "")
	s.schedulesMu.Lock()
	defer s.schedulesMu.Unlock()

	now := time.Now()
	for _, sch := range s.schedules {
		func(sch *ScanSchedule) {
			defer safe.Recover("scheduler."+sch.ID, "")
			if !sch.Enabled {
				return
			}
			if now.After(sch.NextRun) || now.Equal(sch.NextRun) {
				log.Printf("[SCHEDULER] Triggering scheduled scan: %s (Targets: %v)", sch.Name, sch.Targets)

				req := ScanRequest{
					Targets:        sch.Targets,
					Instruction:    sch.Instruction,
					ScanMode:       sch.ScanMode,
					SeverityFilter: sch.SeverityFilter,
					Phases:         sch.Phases,
					ReconMode:      sch.ReconMode,
					ScanIntensity:  sch.ScanIntensity,
					CompanyName:    sch.CompanyName,
					LogoPath:       sch.LogoPath,
					DiscordWebhook: sch.DiscordWebhook,
					Name:           sch.Name + " (Scheduled)",
					Model:          sch.Model,
				}

				scanCfg := *s.cfg
				if sch.Model != "" {
					scanCfg.LLM = sch.Model
				}
				instanceID := randomSlug()

				go s.runMultiScan(req, &scanCfg, instanceID)

				sch.LastRun = now
				sch.NextRun = calculateNextRun(sch.Interval, now)

				if err := s.saveScheduleToDisk(sch); err != nil {
					log.Printf("[SCHEDULER] Error saving triggered schedule %s: %v", sch.ID, err)
				}
			}
		}(sch)
	}
}
