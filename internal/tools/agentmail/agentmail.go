// Package agentmail provides AgentMail API integration for email verification during pentesting.
// This tool should ONLY be used for sign-up/login verification flows.
package agentmail

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const baseURL = "https://api.agentmail.to/v0"

// AgentMail client
type AgentMail struct {
	http *http.Client
}

// Message represents an email message
type Message struct {
	ID            string       `json:"message_id"`
	Subject       string       `json:"subject"`
	From          string       `json:"from"`
	To            string       `json:"to"`
	Text          string       `json:"text"`
	ExtractedText string       `json:"extracted_text"`
	HTMLBody      string       `json:"html"`
	Date          string       `json:"date"`
	CreatedAt     string       `json:"created_at"`
	Attachments   []Attachment `json:"attachments"`
}

// Attachment represents an email attachment
type Attachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	Size        int    `json:"size"`
	ContentType string `json:"content_type"`
}

// Inbox represents an email inbox
type Inbox struct {
	InboxID     string `json:"inbox_id"`
	Email       string `json:"email"`
	PodID       string `json:"pod_id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

// New creates a new AgentMail client
func New() *AgentMail {
	return &AgentMail{
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// buildAuth builds the Bearer authorization header
func (a *AgentMail) buildAuth() string {
	cfg := config.Get()
	return "Bearer " + cfg.AgentMailAPIKey
}

// isConfigured checks if AgentMail is properly configured
func (a *AgentMail) isConfigured() bool {
	cfg := config.Get()
	return cfg.AgentMailAPIKey != ""
}

// ListInboxes lists all inboxes
func (a *AgentMail) ListInboxes() ([]Inbox, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured: set AGENTMAIL_API_KEY environment variable")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("Warning: failed to read API error response: %v", readErr)
		}
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Inboxes []Inbox `json:"inboxes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Inboxes, nil
}

// CreateInbox creates a new inbox with optional username and display name
func (a *AgentMail) CreateInbox(username, displayName string) (*Inbox, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured: set AGENTMAIL_API_KEY environment variable")
	}

	payloadMap := map[string]string{}
	if username != "" {
		payloadMap["username"] = username
	}
	if displayName != "" {
		payloadMap["display_name"] = displayName
	}

	payload, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inbox payload: %w", err)
	}
	req, err := http.NewRequest("POST", baseURL+"/inboxes", strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("Warning: failed to read API error response: %v", readErr)
		}
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(respBody))
	}

	var inbox Inbox
	if err := json.NewDecoder(resp.Body).Decode(&inbox); err != nil {
		return nil, err
	}

	return &inbox, nil
}

// GetInbox gets an inbox by ID
func (a *AgentMail) GetInbox(inboxID string) (*Inbox, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes/"+inboxID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("Warning: failed to read API error response: %v", readErr)
		}
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var inbox Inbox
	if err := json.NewDecoder(resp.Body).Decode(&inbox); err != nil {
		return nil, err
	}

	return &inbox, nil
}

// ListMessages lists messages in an inbox
func (a *AgentMail) ListMessages(inboxID string) ([]Message, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes/"+inboxID+"/messages", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("Warning: failed to read API error response: %v", readErr)
		}
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Messages []Message `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Messages, nil
}

// GetMessage gets a specific message
func (a *AgentMail) GetMessage(inboxID, messageID string) (*Message, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	req, err := http.NewRequest("GET", baseURL+"/inboxes/"+inboxID+"/messages/"+messageID, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.buildAuth())

	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Printf("Warning: failed to read API error response: %v", readErr)
		}
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var msg Message
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

// WaitForEmail waits for a NEW email, optionally matching a subject keyword.
// If subject is empty, returns the first new email that arrives after calling this function.
func (a *AgentMail) WaitForEmail(inboxID, subject string, timeout time.Duration) (*Message, error) {
	if !a.isConfigured() {
		return nil, fmt.Errorf("AgentMail not configured")
	}

	// Snapshot existing message IDs so we only return NEW emails
	existingIDs := map[string]bool{}
	if existing, err := a.ListMessages(inboxID); err == nil {
		for _, m := range existing {
			existingIDs[m.ID] = true
		}
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	timeoutChan := time.After(timeout)

	for {
		select {
		case <-timeoutChan:
			hint := subject
			if hint == "" {
				hint = "(any)"
			}
			return nil, fmt.Errorf("timeout waiting for email with subject containing: %s (waited %v)", hint, timeout)
		case <-ticker.C:
			messages, err := a.ListMessages(inboxID)
			if err != nil {
				continue
			}
			for _, msg := range messages {
				// Skip messages that existed before we started waiting
				if existingIDs[msg.ID] {
					continue
				}
				// If subject filter is set, match it
				if subject != "" && !strings.Contains(strings.ToLower(msg.Subject), strings.ToLower(subject)) {
					continue
				}
				return &msg, nil
			}
		}
	}
}

// Register registers the agentmail tool with the registry
func Register(r *tools.Registry) {
	am := New()

	// Check if configured
	if !am.isConfigured() {
		return // Skip registration if not configured
	}

	r.Register(&tools.Tool{
		Name: "agentmail",
		Description: `Create temporary email inboxes to test SIGN-UP and LOGIN flows on target applications.
USE ONLY FOR:
- Creating accounts on the target to test authenticated vulnerabilities (IDOR, auth bypass, privilege escalation)
- Receiving verification/confirmation emails during sign-up
- Receiving password reset emails to test reset flow vulnerabilities
- Receiving OTP/2FA codes

DO NOT USE FOR: sending phishing emails, spamming, or any purpose other than testing authentication flows on the target.

WORKFLOW:
1. create_inbox → get a temporary email address
2. Use the email to sign up on the target application
3. wait_for_email → receive the verification email
4. Extract the verification link/code from the email body
5. Complete registration and test authenticated endpoints`,
		Parameters: []tools.Parameter{
			{Name: "action", Description: "Action: create_inbox, list_inboxes, get_inbox, list_messages, get_message, wait_for_email", Required: true},
			{Name: "inbox_id", Description: "Inbox ID (required for get_inbox, list_messages, get_message, wait_for_email)", Required: false},
			{Name: "username", Description: "Desired email username/prefix (for create_inbox, optional — random if omitted)", Required: false},
			{Name: "display_name", Description: "Display name for the inbox (for create_inbox, optional)", Required: false},
			{Name: "subject", Description: "Subject keyword to match (for wait_for_email — partial match, case-insensitive)", Required: false},
			{Name: "message_id", Description: "Message ID (for get_message)", Required: false},
			{Name: "timeout", Description: "Timeout in seconds for wait_for_email (default: 300 = 5 min)", Required: false},
		},
		Execute: func(args map[string]string) (tools.Result, error) {
			action := args["action"]
			var output string

			switch action {
			case "list_inboxes":
				inboxes, err := am.ListInboxes()
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				for _, ib := range inboxes {
					output += fmt.Sprintf("Inbox ID: %s | Email: %s\n", ib.InboxID, ib.Email)
				}
				if output == "" {
					output = "No inboxes found. Use action=create_inbox to create one."
				}

			case "create_inbox":
				username := args["username"]
				displayName := args["display_name"]
				inbox, err := am.CreateInbox(username, displayName)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = fmt.Sprintf("✅ Inbox created!\nInbox ID: %s\nEmail: %s\n\nUse this email address to sign up on the target. Then use action=wait_for_email with inbox_id=%s to receive the verification email.", inbox.InboxID, inbox.Email, inbox.InboxID)

			case "get_inbox":
				inboxID := args["inbox_id"]
				if inboxID == "" {
					return tools.Result{Output: "Error: inbox_id is required"}, nil
				}
				inbox, err := am.GetInbox(inboxID)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				output = fmt.Sprintf("Inbox ID: %s\nEmail: %s\nDisplay Name: %s\nCreated: %s", inbox.InboxID, inbox.Email, inbox.DisplayName, inbox.CreatedAt)

			case "list_messages":
				inboxID := args["inbox_id"]
				if inboxID == "" {
					return tools.Result{Output: "Error: inbox_id is required"}, nil
				}
				messages, err := am.ListMessages(inboxID)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				for _, m := range messages {
					output += fmt.Sprintf("ID: %s | From: %s | Subject: %s | Date: %s\n", m.ID, m.From, m.Subject, m.CreatedAt)
				}
				if output == "" {
					output = "No messages found yet. The verification email may not have arrived yet — try wait_for_email."
				}

			case "get_message":
				inboxID := args["inbox_id"]
				msgID := args["message_id"]
				if inboxID == "" || msgID == "" {
					return tools.Result{Output: "Error: inbox_id and message_id are required"}, nil
				}
				msg, err := am.GetMessage(inboxID, msgID)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error()}, nil
				}
				// Prefer extracted_text (stripped of reply chains) over raw text
				body := msg.ExtractedText
				if body == "" {
					body = msg.Text
				}
				output = fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\nDate: %s\n\n%s", msg.From, msg.To, msg.Subject, msg.CreatedAt, body)

			case "wait_for_email":
				inboxID := args["inbox_id"]
				subject := args["subject"]
				if inboxID == "" {
					return tools.Result{Output: "Error: inbox_id is required"}, nil
				}
				if subject == "" {
					subject = "" // Match any email
				}
				timeout := 300 // 5 minutes default
				if t, ok := args["timeout"]; ok && t != "" {
					_, _ = fmt.Sscanf(t, "%d", &timeout)
				}
				msg, err := am.WaitForEmail(inboxID, subject, time.Duration(timeout)*time.Second)
				if err != nil {
					return tools.Result{Output: "Error: " + err.Error() + "\n\nTip: The email may take longer to arrive. Try increasing the timeout, or check list_messages to see what's arrived."}, nil
				}
				body := msg.ExtractedText
				if body == "" {
					body = msg.Text
				}
				output = fmt.Sprintf("✅ Email received!\nFrom: %s\nSubject: %s\n\n%s", msg.From, msg.Subject, body)

				// Auto-extract verification/confirmation URLs
				verifyURL := extractVerificationURL(body)
				if verifyURL == "" && msg.HTMLBody != "" {
					verifyURL = extractVerificationURL(msg.HTMLBody)
				}
				if verifyURL != "" {
					output += fmt.Sprintf("\n\n🔗 VERIFICATION LINK DETECTED:\n%s\n\nUse: browser_action command=goto url=%s", verifyURL, verifyURL)
				}

			default:
				output = "Unknown action. Available actions: create_inbox, list_inboxes, get_inbox, list_messages, get_message, wait_for_email"
			}

			return tools.Result{Output: output}, nil
		},
	})
}

// extractVerificationURL finds verification/confirmation URLs in email text.
func extractVerificationURL(text string) string {
	// Common verification URL patterns
	urlRegex := regexp.MustCompile(`https?://[^\s<>"']+(?:verif|confirm|activate|valid|token|auth|callback|reset|click)[^\s<>"']*`)
	match := urlRegex.FindString(text)
	if match != "" {
		return strings.TrimRight(match, ".,;:!)]}>")
	}

	// Fallback: find any URL with a long token/hash parameter
	tokenURLRegex := regexp.MustCompile(`https?://[^\s<>"']*[?&][^\s<>"']*=[a-zA-Z0-9_-]{20,}[^\s<>"']*`)
	match = tokenURLRegex.FindString(text)
	if match != "" {
		return strings.TrimRight(match, ".,;:!)]}>")
	}

	return ""
}
