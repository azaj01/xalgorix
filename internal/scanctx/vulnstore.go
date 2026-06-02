package scanctx

import (
	"encoding/json"
	"fmt"
	"sync"
)

// VulnStore provides per-session vulnerability storage,
// replacing the global vulnerabilities slice in reporting.go.

type VulnStore struct {
	mu    sync.RWMutex
	vulns []map[string]interface{}
}

// NewVulnStore creates an empty vulnerability store.
func NewVulnStore() *VulnStore {
	return &VulnStore{
		vulns: make([]map[string]interface{}, 0),
	}
}

// Add appends a vulnerability (as a generic map) to the store.
func (vs *VulnStore) Add(vuln map[string]interface{}) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.vulns = append(vs.vulns, vuln)
}

// GetAll returns a copy of all vulnerabilities.
func (vs *VulnStore) GetAll() []map[string]interface{} {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	result := make([]map[string]interface{}, len(vs.vulns))
	copy(result, vs.vulns)
	return result
}

// Count returns the number of stored vulnerabilities.
func (vs *VulnStore) Count() int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return len(vs.vulns)
}

// Reset clears all vulnerabilities.
// Uses an empty slice (not nil) to match NewVulnStore() behavior
// and ensure consistent JSON marshaling ([] instead of null).
func (vs *VulnStore) Reset() {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.vulns = make([]map[string]interface{}, 0)
}

// ToJSON returns vulnerabilities as a JSON string.
// Returns an error if marshaling fails, allowing callers to handle it properly.
func (vs *VulnStore) ToJSON() (string, error) {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	data, err := json.Marshal(vs.vulns)
	if err != nil {
		return "", fmt.Errorf("vulnstore marshal: %w", err)
	}
	return string(data), nil
}
