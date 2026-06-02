// Shared JSON error envelope used by the org / workspace / member
// handlers (and extended by later phases for the full public REST
// surface). Centralising the helper keeps every handler's error
// response shape stable so the Dashboard and API_Key clients can
// switch on the machine-readable `error` code without hunting
// through human-readable strings.
//
// Created by task 3.6 — `Org/workspace/member endpoints`.
// Requirements: 4.1, 4.6, 4.10, 8.1.
package api

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the canonical JSON shape returned on every 4xx /
// 5xx response. The `error` field is the machine-readable code; the
// optional `message` field is a human-readable hint suitable for
// developer console output. Avoid exposing internal details in
// `message` (e.g. SQL state, stack frames) — leak channels go
// through the logger and audit log instead.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// writeError emits the canonical JSON error envelope at the given
// status code. The Content-Type is forced to application/json so
// browser dev tools render the body correctly even when the request
// did not advertise an Accept header.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The encoder cannot fail on a tiny struct of strings.
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: code, Message: message})
}

// writeJSON emits the supplied value as JSON at status with the
// `application/json` Content-Type. A nil body is encoded as the JSON
// `null` literal so clients always see a well-formed response.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
