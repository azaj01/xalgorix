// Package providers — error sentinels for the Catalog_Service.
//
// This file declares the cross-handler error sentinels that callers in
// internal/web (Wave E task 5.1) match with errors.Is to pick the
// correct HTTP status code. Validation-style sentinels live in
// types.go because they're keyed off Entry shape, not Service state.
package providers

import "errors"

// ErrCatalogCorrupt is returned from every Service write path when
// the on-disk catalog file failed JSON validation at startup. Reads
// (List/Get) instead behave as if the catalog were empty so the rest
// of the system keeps serving traffic; only mutations are refused.
//
// Per the design, the HTTP layer maps this to 503 Service Unavailable
// so the operator can see "catalog corrupt: refuse writes" in the
// dashboard and either repair or remove the file before retrying.
//
// Validates: Requirement 1.7.
var ErrCatalogCorrupt = errors.New("catalog corrupt: refuse writes")

// ErrIDInvalid is returned from Service.Create / Service.Update when
// the supplied id does not satisfy idRE (Requirement 1.2). Mapped to
// HTTP 400 by the web layer.
var ErrIDInvalid = errors.New("id must match ^[a-z0-9][a-z0-9_-]{0,63}$")

// ErrIDMismatch is returned from Service.Update when the URL-path id
// disagrees with the Entry.ID in the request body. The two must
// agree so the caller cannot rename an entry through Update.
var ErrIDMismatch = errors.New("id in path does not match id in body")

// ErrIDExists is returned from Service.Create when the supplied id is
// already present in the catalog. Mapped to HTTP 409 by the web layer.
var ErrIDExists = errors.New("id already exists")

// ErrNotFound is returned from Service.Update / Service.Delete /
// Service.Get callers when the requested id is not in the catalog.
// Service.Get also signals this case via its (Entry, false, nil) tuple
// for callers that prefer the boolean form.
var ErrNotFound = errors.New("provider not found")
