// Package providers — openclaw catalog importer.
//
// ImportOpenclaw fetches a remote openclaw provider directory over
// HTTPS, merges its entries into the in-memory + on-disk catalog with
// skip-on-collision semantics (Requirements 3.1, 3.2), and reports a
// per-id outcome list back to the caller.
//
// Behavioral contract encoded in this file:
//
//   - HTTPS-only fetch (per design's loopback / outbound-security
//     requirement). Any non-https scheme is rejected up front so we
//     never issue a plaintext request to an arbitrary host.
//
//   - On any non-2xx upstream response the function returns
//     ErrUpstream{StatusCode, Body} and leaves the local catalog
//     completely untouched (Requirement 3.4). The HTTP layer
//     (Wave E task 5.1) maps ErrUpstream to 502 with the upstream
//     status + body envelope.
//
//   - Merge policy: the local catalog wins on every id collision.
//     Imported ids that already exist locally are emitted with
//     Action="skipped", Reason="id_exists" (Requirement 3.2). Ids
//     that do not yet exist locally are validated through
//     validateEntry / idRE and emitted with Action="imported" before
//     being added to the candidate snapshot. Invalid entries from the
//     upstream document are skipped+logged rather than aborting the
//     merge so a single typo upstream cannot wedge the import.
//
//   - The on-disk file is rewritten through Service.flushLocked
//     (the same atomic temp+rename path used by Create/Update/Delete)
//     and only after every entry in the document has been merged,
//     so a partial merge is never observable on disk.
//
//   - Concurrency: the merge holds Service.mu for write end-to-end
//     so a parallel Create/Update/Delete cannot interleave with the
//     import. The HTTP fetch happens BEFORE the lock is taken so the
//     network round-trip does not block readers.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
)

// ImportOutcome captures the per-id result of an openclaw merge.
// Action is one of "imported" or "skipped"; Reason is set to
// "id_exists" when the id was already present locally and left empty
// otherwise. The shape matches the JSON envelope defined in the
// design document and consumed by the dashboard's openclaw-import
// component (Wave F task 6.4).
//
// Validates: Requirements 3.1, 3.2.
type ImportOutcome struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

// ImportResult is the return shape from ImportOpenclaw. It carries
// one ImportOutcome per id observed in the upstream document, in the
// document's iteration order, so the dashboard can render the import
// summary deterministically.
type ImportResult struct {
	Outcomes []ImportOutcome `json:"outcomes"`
}

// ErrUpstream is returned by ImportOpenclaw when the openclaw fetch
// returned a non-2xx HTTP status. The web layer maps this to HTTP
// 502 with the upstream status code + body in a JSON envelope so the
// operator can see why the import refused (Requirement 3.4).
//
// ErrUpstream is a value-type error so it can be both returned by
// value (the design's `ErrUpstream{StatusCode, Body}` form) and
// matched with errors.As.
type ErrUpstream struct {
	StatusCode int
	Body       string
}

// Error implements the error interface so ErrUpstream satisfies the
// error contract. The message keeps the upstream status visible
// without dumping the entire response body into log lines, while
// still preserving Body on the struct for the HTTP envelope.
func (e ErrUpstream) Error() string {
	return fmt.Sprintf("openclaw upstream returned status %d", e.StatusCode)
}

// openclawDocument is a tolerant decode target for the upstream
// document. The openclaw directory is canonically a JSON array of
// Entry objects, but some mirrors wrap the array in a {"providers":
// [...]} envelope — we accept either by attempting both decodes in
// order.
type openclawDocument struct {
	Providers []Entry `json:"providers"`
}

// ImportOpenclaw fetches the openclaw provider directory at url over
// HTTPS, merges its entries into the local catalog with skip-on-
// collision semantics, and returns one outcome per id seen in the
// document.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4.
func (s *Service) ImportOpenclaw(ctx context.Context, url string) (ImportResult, error) {
	if err := ctx.Err(); err != nil {
		return ImportResult{}, err
	}

	// HTTPS-only: refuse plaintext (or otherwise non-https) URLs so
	// an attacker cannot redirect the import through a MITM by
	// substituting an http:// catalog URL.
	parsed, err := neturl.Parse(url)
	if err != nil {
		return ImportResult{}, fmt.Errorf("providers: parse openclaw url %q: %w", url, err)
	}
	if parsed.Scheme != "https" {
		return ImportResult{}, fmt.Errorf("providers: openclaw url must use https scheme (got %q)", parsed.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ImportResult{}, fmt.Errorf("providers: build openclaw request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return ImportResult{}, fmt.Errorf("providers: fetch openclaw: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ImportResult{}, fmt.Errorf("providers: read openclaw body: %w", err)
	}

	// Non-2xx → preserve the local catalog and surface the upstream
	// envelope to the caller. Requirement 3.4.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ImportResult{}, ErrUpstream{StatusCode: resp.StatusCode, Body: string(body)}
	}

	// Try the canonical bare-array shape first, then fall back to
	// the {"providers": [...]} envelope. Either form is accepted so
	// the dashboard does not have to care which mirror it pointed at.
	var entries []Entry
	if uerr := json.Unmarshal(body, &entries); uerr != nil {
		var env openclawDocument
		if eerr := json.Unmarshal(body, &env); eerr != nil {
			return ImportResult{}, fmt.Errorf("providers: decode openclaw document: %w", uerr)
		}
		entries = env.Providers
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Refuse the import while the on-disk catalog is corrupt — the
	// operator must repair or remove the file before mutations
	// resume. This matches the Create/Update/Delete contract in
	// service.go (Requirement 1.7).
	if s.bad {
		return ImportResult{}, ErrCatalogCorrupt
	}

	next := cloneSnap(s.snap)
	outcomes := make([]ImportOutcome, 0, len(entries))
	imported := 0

	for _, e := range entries {
		// Validate each entry against the same rules a Create call
		// would face. Skip+log invalid entries rather than aborting
		// the merge so one bad upstream row cannot wedge the whole
		// import.
		if !idRE.MatchString(e.ID) {
			s.log.Printf("providers: openclaw entry has invalid id %q; skipping", e.ID)
			continue
		}
		if verr := validateEntry(e); verr != nil {
			s.log.Printf("providers: openclaw entry %q failed validation: %v; skipping", e.ID, verr)
			continue
		}

		if _, exists := next[e.ID]; exists {
			// Local entry wins. Requirement 3.2.
			outcomes = append(outcomes, ImportOutcome{
				ID:     e.ID,
				Action: "skipped",
				Reason: "id_exists",
			})
			continue
		}

		next[e.ID] = e
		outcomes = append(outcomes, ImportOutcome{
			ID:     e.ID,
			Action: "imported",
		})
		imported++
	}

	// Only flush when the merge actually changed the catalog.
	// Skipping the write when nothing was imported keeps the on-disk
	// file byte-identical to its pre-import contents, which lines up
	// with the property test that asserts no on-disk drift in the
	// no-op case.
	if imported > 0 {
		if err := s.flushLocked(next); err != nil {
			return ImportResult{}, err
		}
		s.snap = next
	}

	return ImportResult{Outcomes: outcomes}, nil
}
