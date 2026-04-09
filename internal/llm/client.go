// Package llm provides the LLM API client for Xalgorix.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// StreamChunk is a piece of streaming response.
type StreamChunk struct {
	Content string
	Done    bool
	Err     error
}

// Client is the LLM API client.
type Client struct {
	cfg        *config.Config
	httpClient *http.Client
	apiModel   string
	mu         sync.Mutex
	totalIn    int
	totalOut   int
	ctx        context.Context // agent context for cancellation
}

// TokenUsage holds cumulative token counts.
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// GetTokens returns cumulative token usage.
func (c *Client) GetTokens() (promptTokens, completionTokens, totalTokens int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalIn, c.totalOut, c.totalIn + c.totalOut
}

// NewClient creates a new LLM client.
func NewClient(cfg *config.Config) *Client {
	apiModel := cfg.ResolveModel()
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Minute},
		apiModel:   apiModel,
		ctx:        context.Background(), // default context, overridden by SetContext
	}
}

// SetContext sets the context for HTTP requests, enabling cancellation.
func (c *Client) SetContext(ctx context.Context) {
	c.ctx = ctx
}

// chatRequest is the OpenAI-compatible chat completion request.
type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

// chatChoice represents a response choice.
type chatChoice struct {
	Delta   struct{ Content string } `json:"delta"`
	Message struct{ Content string } `json:"message"`
}

// chatResponse is the OpenAI-compatible response.
type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Usage   *TokenUsage  `json:"usage,omitempty"`
}

// resolveEndpoint returns the full chat completions URL and clean model name.
// Handles provider prefixes like "minimax/", "openai/", "anthropic/", etc.
// Auto-appends /v1/chat/completions if the base doesn't already contain /v1.
// Also supports custom providers - just set XALGORIX_API_BASE to your endpoint.
func (c *Client) resolveEndpoint() (string, string) {
	apiBase := c.cfg.APIBase
	model := c.apiModel

	// Extract provider prefix if present (e.g., "openai/gpt-5.4" -> provider="openai", model="gpt-5.4")
	provider := ""
	if idx := strings.Index(model, "/"); idx >= 0 {
		provider = strings.ToLower(model[:idx])
		model = model[idx+1:]
	}

	// Provider prefix in model name is the source of truth for API base.
	// XALGORIX_API_BASE is only used for unknown/custom providers.
	providerBases := map[string]string{
		"openai":    "https://api.openai.com/v1",
		"anthropic": "https://api.anthropic.com",
		"minimax":   "https://api.minimax.io/v1",
		"deepseek":  "https://api.deepseek.com/v1",
		"groq":      "https://api.groq.com/openai/v1",
		"ollama":    "http://localhost:11434/v1",
		"google":    "https://generativelanguage.googleapis.com/v1",
		"gemini":    "https://generativelanguage.googleapis.com/v1",
	}

	if knownBase, ok := providerBases[provider]; ok {
		// Known provider — always use its correct base, ignore XALGORIX_API_BASE
		apiBase = knownBase
	} else if apiBase == "" {
		// Unknown/no provider and no API base set — default to OpenAI
		apiBase = "https://api.openai.com/v1"
	}

	apiBase = strings.TrimRight(apiBase, "/")

	// Build the URL based on provider
	url := apiBase
	if strings.Contains(apiBase, "anthropic") {
		// Anthropic uses /v1/messages
		if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
			url += "/v1"
		}
		url += "/messages"
	} else if strings.Contains(apiBase, "google") || strings.Contains(apiBase, "generativelanguage") {
		// Google Gemini uses /v1beta/models/MODEL:generateContent
		url += "beta/models/" + model + ":generateContent"
	} else {
		if !strings.HasSuffix(apiBase, "/v1") && !strings.Contains(apiBase, "/v1/") {
			url += "/v1"
		}
		url += "/chat/completions"
	}

	return url, model
}

// Chat sends a non-streaming chat request and returns the full response.
func (c *Client) Chat(messages []Message) (string, error) {
	return c.chatWithRetry(messages)
}

func (c *Client) chatWithRetry(messages []Message) (string, error) {
	maxRetries := c.cfg.LLMMaxRetries
	if maxRetries < 3 {
		maxRetries = 3
	}
	var lastErr error

	for attempt := range maxRetries {
		if attempt > 0 {
			// Smart backoff based on error type
			backoff := time.Duration(attempt*3) * time.Second
			if lastErr != nil {
				errStr := lastErr.Error()
				if strings.Contains(errStr, "429") || strings.Contains(errStr, "rate") {
					backoff = 30 * time.Second // rate limit: wait longer
				} else if strings.Contains(errStr, "connection") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "EOF") {
					backoff = time.Duration(attempt*10) * time.Second // network: longer backoff
				} else if strings.Contains(errStr, "500") || strings.Contains(errStr, "502") || strings.Contains(errStr, "503") {
					backoff = time.Duration(attempt*5) * time.Second // server error
				}
			}
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			log.Printf("[llm] Retry %d/%d after %s (last error: %v)", attempt+1, maxRetries, backoff, lastErr)
			time.Sleep(backoff)
		}

		// Check if context is cancelled before retrying
		if c.ctx != nil && c.ctx.Err() != nil {
			return "", fmt.Errorf("LLM request cancelled: %w", c.ctx.Err())
		}

		result, err := c.doChat(messages)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}

	return "", fmt.Errorf("LLM request failed after %d retries: %w", maxRetries, lastErr)
}

// ChatStream sends a streaming chat request and returns a channel of chunks.
func (c *Client) ChatStream(messages []Message) <-chan StreamChunk {
	ch := make(chan StreamChunk, 64)

	go func() {
		defer close(ch)

		url, model := c.resolveEndpoint()

		reqBody := chatRequest{
			Model:    model,
			Messages: messages,
			Stream:   true,
		}

		body, err := json.Marshal(reqBody)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("failed to marshal request: %w", err)}
			return
		}
		reqCtx := c.ctx
		if reqCtx == nil {
			reqCtx = context.Background()
		}
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			ch <- StreamChunk{Err: err}
			return
		}

		req.Header.Set("Content-Type", "application/json")
		if c.cfg.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			ch <- StreamChunk{Err: fmt.Errorf("request failed: %w", err)}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				ch <- StreamChunk{Err: fmt.Errorf("API returned %d (failed to read body: %v)", resp.StatusCode, readErr)}
				return
			}
			ch <- StreamChunk{Err: fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))}
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		// Increase scanner buffer for large SSE chunks
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}

			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				ch <- StreamChunk{Done: true}
				return
			}

			var sseResp chatResponse
			if err := json.Unmarshal([]byte(data), &sseResp); err != nil {
				continue
			}

			// Track token usage from streaming (often in the final chunk)
			if sseResp.Usage != nil {
				c.mu.Lock()
				c.totalIn += sseResp.Usage.PromptTokens
				c.totalOut += sseResp.Usage.CompletionTokens
				c.mu.Unlock()
			}

			if len(sseResp.Choices) > 0 {
				content := sseResp.Choices[0].Delta.Content
				if content != "" {
					ch <- StreamChunk{Content: content}
				}
			}
		}

		ch <- StreamChunk{Done: true}
	}()

	return ch
}

// doChat performs a single non-streaming API call.
func (c *Client) doChat(messages []Message) (string, error) {
	url, model := c.resolveEndpoint()
	log.Printf("[llm] Request → URL=%s model=%s apiModel=%s cfgLLM=%s cfgAPIBase=%s", url, model, c.apiModel, c.cfg.LLM, c.cfg.APIBase)

	reqBody := chatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}
	// Use agent context so cancel/stop can interrupt this request
	reqCtx := c.ctx
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	// Track token usage
	if chatResp.Usage != nil {
		c.mu.Lock()
		c.totalIn += chatResp.Usage.PromptTokens
		c.totalOut += chatResp.Usage.CompletionTokens
		c.mu.Unlock()
	}

	return chatResp.Choices[0].Message.Content, nil
}
