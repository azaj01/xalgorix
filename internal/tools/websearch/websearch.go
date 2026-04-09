// Package websearch provides web search tools.
package websearch

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	netURL "net/url"
	"strings"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// Register adds web search tools to the registry.
func Register(r *tools.Registry) {
	r.Register(&tools.Tool{
		Name:        "web_search",
		Description: "Search the web for information. Uses Google/Bing/Brave.",
		Parameters: []tools.Parameter{
			{Name: "query", Description: "Search query", Required: true},
			{Name: "max_results", Description: "Maximum results (default: 10)", Required: false},
		},
		Execute: webSearch,
	})
	r.Register(&tools.Tool{
		Name:        "cve_search",
		Description: "Search for CVE vulnerabilities. Uses NIST NVD API.",
		Parameters: []tools.Parameter{
			{Name: "cve_id", Description: "CVE ID (e.g., CVE-2024-1234)", Required: true},
		},
		Execute: cveSearch,
	})
	r.Register(&tools.Tool{
		Name:        "exploit_search",
		Description: "Search for exploits. Uses Exploit-DB.",
		Parameters: []tools.Parameter{
			{Name: "query", Description: "Search query (product, version, keyword)", Required: true},
		},
		Execute: exploitSearch,
	})
}

func webSearch(args map[string]string) (tools.Result, error) {
	query := args["query"]
	if query == "" {
		return tools.Result{}, fmt.Errorf("query is required")
	}

	maxResults := 10
	if m := args["max_results"]; m != "" {
		fmt.Sscanf(m, "%d", &maxResults)
	}

	// Try Gemini first if API key is configured
	results, err := searchGemini(query, maxResults)
	if err == nil && len(results) > 0 {
		return formatResults(query, results), nil
	}

	// Fallback to Brave
	results, err = searchBrave(query, maxResults)
	if err == nil && len(results) > 0 {
		return formatResults(query, results), nil
	}

	// Fallback to Google scraping
	results, err = searchGoogle(query, maxResults)
	if err == nil && len(results) > 0 {
		return formatResults(query, results), nil
	}

	// Fallback to Bing
	results, err = searchBing(query, maxResults)
	if err == nil && len(results) > 0 {
		return formatResults(query, results), nil
	}

	// Final fallback to DuckDuckGo
	results, err = searchDuckDuckGo(query, maxResults)
	if err != nil {
		return tools.Result{}, fmt.Errorf("all search engines failed: %w", err)
	}

	return formatResults(query, results), nil
}

type searchResult struct {
	Title   string
	URL     string
	Snippet string
}

func formatResults(query string, results []searchResult) tools.Result {
	if len(results) == 0 {
		return tools.Result{Output: fmt.Sprintf("No results found for: %s\n", query)}
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Search results for: %s\n\n", query))

	for i, r := range results {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, r.Title))
		b.WriteString(fmt.Sprintf("   URL: %s\n", r.URL))
		if r.Snippet != "" {
			b.WriteString(fmt.Sprintf("   %s\n", r.Snippet))
		}
		b.WriteString("\n")
	}

	return tools.Result{Output: b.String()}
}

// searchBrave scrapes Brave Search results
func searchBrave(query string, max int) ([]searchResult, error) {
	// Try Brave's JSON API (more reliable)
	url := fmt.Sprintf("https://search.brave.com/api/search?q=%s&count=%d", netURL.QueryEscape(query), max)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Brave search request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("brave API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Brave response: %w", err)
	}

	var brave struct {
		WebResults []struct {
			Title string `json:"title"`
			URL   string `json:"url"`
			Desc  string `json:"description"`
		} `json:"web"`
	}

	if err := json.Unmarshal(body, &brave); err != nil {
		return nil, err
	}

	var results []searchResult
	for _, r := range brave.WebResults {
		if len(results) >= max {
			break
		}
		results = append(results, searchResult{
			Title:   r.Title,
			URL:     r.URL,
			Snippet: r.Desc,
		})
	}

	return results, nil
}

// searchGoogle scrapes Google search results
func searchGoogle(query string, max int) ([]searchResult, error) {
	url := fmt.Sprintf("https://www.google.com/search?q=%s&num=%d", netURL.QueryEscape(query), max)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Google search request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google response: %w", err)
	}
	html := string(body)

	var results []searchResult

	// Parse Google results
	parts := strings.Split(html, `<div class="BNeawe`)
	for _, part := range parts {
		if strings.Contains(part, "http") {
			urlStart := strings.Index(part, "http")
			if urlStart > 0 {
				urlEnd := strings.Index(part[urlStart:], "&")
				if urlEnd < 0 {
					urlEnd = len(part[urlStart:])
				}
				if urlEnd > 0 {
					results = append(results, searchResult{
						URL: part[urlStart : urlStart+urlEnd],
					})
				}
			}
		}
		if len(results) >= max {
			break
		}
	}

	return results, nil
}

// searchBing scrapes Bing search results
func searchBing(query string, max int) ([]searchResult, error) {
	url := fmt.Sprintf("https://www.bing.com/search?q=%s&count=%d", netURL.QueryEscape(query), max)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bing search request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Bing response: %w", err)
	}
	html := string(body)

	var results []searchResult

	// Parse Bing results
	parts := strings.Split(html, `class="b_attrib"`)
	for _, part := range parts {
		idx := strings.Index(part, "href=\"")
		if idx > 0 && idx < 100 {
			urlEnd := strings.Index(part[idx+6:], "\"")
			if urlEnd > 0 {
				results = append(results, searchResult{
					URL: part[idx+6 : idx+6+urlEnd],
				})
			}
		}
		if len(results) >= max {
			break
		}
	}

	return results, nil
}

// searchDuckDuckGo uses the HTML version
func searchDuckDuckGo(query string, max int) ([]searchResult, error) {
	// Try JSON API first (more reliable)
	url := fmt.Sprintf("https://api.duckduckgo.com/?q=%s&format=json&no_html=1&skip_disambig=1", netURL.QueryEscape(query))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				log.Printf("Warning: failed to read DuckDuckGo JSON response: %v", readErr)
			} else {
				var ddg struct {
					AbstractText string `json:"AbstractText"`
					AbstractURL  string `json:"AbstractURL"`
					Results      []struct {
						Text string `json:"Text"`
						URL  string `json:"URL"`
					} `json:"RelatedTopics"`
				}

				if err := json.Unmarshal(body, &ddg); err != nil {
					log.Printf("Warning: failed to parse DuckDuckGo JSON: %v", err)
				}

				var results []searchResult
				if ddg.AbstractText != "" {
					results = append(results, searchResult{
						Title:   ddg.AbstractText[:min(100, len(ddg.AbstractText))],
						URL:     ddg.AbstractURL,
						Snippet: ddg.AbstractText,
					})
				}

				for _, r := range ddg.Results {
					if len(results) >= max {
						break
					}
					results = append(results, searchResult{
						Title: r.Text,
						URL:   r.URL,
					})
				}

				if len(results) > 0 {
					return results, nil
				}
			}
		}
	}

	// Fallback to HTML scraping
	url = fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", netURL.QueryEscape(query))

	clientHTML := &http.Client{Timeout: 30 * time.Second}
	resp, err = clientHTML.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DuckDuckGo HTML response: %w", err)
	}
	html := string(body)

	var results []searchResult

	// Parse DuckDuckGo HTML results
	parts := strings.Split(html, `class="result__a"`)
	for _, part := range parts {
		idx := strings.Index(part, "href=\"")
		if idx > 0 && idx < 50 {
			urlEnd := strings.Index(part[idx+6:], "\"")
			if urlEnd > 0 {
				url := part[idx+6 : idx+6+urlEnd]
				titleIdx := strings.Index(part, ">")
				titleEnd := strings.Index(part[titleIdx:], "<")
				title := ""
				if titleEnd > 0 && titleIdx < 50 {
					title = part[titleIdx+1 : titleIdx+titleEnd]
				}
				results = append(results, searchResult{
					Title: title,
					URL:   url,
				})
			}
		}
		if len(results) >= max {
			break
		}
	}

	return results, nil
}

// searchGemini uses Google Gemini API for web search
func searchGemini(query string, max int) ([]searchResult, error) {
	cfg := config.Get()
	apiKey := cfg.GeminiAPIKey

	if apiKey == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY not configured")
	}

	// Use Gemini's generateContent with grounding (search)
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent?key=%s", apiKey)

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]interface{}{
					{"text": "Search the web for: " + query + ". Provide up to " + fmt.Sprintf("%d", max) + " relevant results with titles, URLs, and brief descriptions."},
				},
			},
		},
		"tools": []map[string]interface{}{
			{
				"google_search": map[string]interface{}{},
			},
		},
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Gemini request: %w", err)
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Gemini response: %w", err)
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return nil, fmt.Errorf("failed to parse Gemini response: %w", err)
	}

	var results []searchResult
	for _, candidate := range geminiResp.Candidates {
		for _, part := range candidate.Content.Parts {
			// Parse the response for search results
			text := part.Text
			// Extract URLs and titles from the text
			lines := strings.Split(text, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "http") {
					// Extract URL
					urlStart := strings.Index(line, "http")
					if urlStart >= 0 {
						urlEnd := strings.Index(line[urlStart:], " ")
						if urlEnd < 0 {
							urlEnd = len(line[urlStart:])
						}
						url := line[urlStart : urlStart+urlEnd]
						// Clean up URL
						url = strings.TrimSuffix(url, ".")
						if len(results) < max {
							results = append(results, searchResult{
								Title:   strings.TrimSpace(line[:urlStart]),
								URL:     url,
								Snippet: "",
							})
						}
					}
				}
			}
		}
	}

	return results, nil
}

// cveSearch queries the NIST NVD API for CVE details
func cveSearch(args map[string]string) (tools.Result, error) {
	cveID := args["cve_id"]
	if cveID == "" {
		return tools.Result{}, fmt.Errorf("cve_id is required")
	}

	cveID = strings.ToUpper(cveID)
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", netURL.QueryEscape(cveID))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return tools.Result{}, fmt.Errorf("CVE search failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return tools.Result{Output: fmt.Sprintf("CVE not found: %s\n", cveID)}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return tools.Result{Output: fmt.Sprintf("Failed to read CVE API response for %s: %v\n", cveID, err)}, nil
	}

	var nvd struct {
		ResultsPerPage  int `json:"resultsPerPage"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Description  struct {
					Lang  string `json:"language"`
					Value string `json:"value"`
				} `json:"description"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore          float64 `json:"baseScore"`
							BaseSeverity       string  `json:"baseSeverity"`
							AttackVector       string  `json:"attackVector"`
							AttackComplexity   string  `json:"attackComplexity"`
							PrivilegesRequired string  `json:"privilegesRequired"`
							UserInteraction    string  `json:"userInteraction"`
							Scope              string  `json:"scope"`
						} `json:"cvssData"`
					} `json:"CVSSMetric_V31"`
				} `json:"metrics"`
				References []struct {
					URL    string `json:"url"`
					Source string `json:"source"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &nvd); err != nil {
		return tools.Result{Output: fmt.Sprintf("Failed to parse CVE response for %s\n", cveID)}, nil
	}

	if nvd.ResultsPerPage == 0 {
		return tools.Result{Output: fmt.Sprintf("CVE not found: %s\n", cveID)}, nil
	}

	var b strings.Builder
	for _, vuln := range nvd.Vulnerabilities {
		cve := vuln.CVE
		b.WriteString(fmt.Sprintf("=== %s ===\n\n", cve.ID))
		b.WriteString(fmt.Sprintf("Published: %s\n", cve.Published))
		b.WriteString(fmt.Sprintf("Last Modified: %s\n\n", cve.LastModified))

		if cve.Description.Value != "" {
			b.WriteString(fmt.Sprintf("Description:\n%s\n\n", cve.Description.Value))
		}

		if len(cve.Metrics.CvssMetricV31) > 0 {
			cvss := cve.Metrics.CvssMetricV31[0].CvssData
			b.WriteString(fmt.Sprintf("CVSS v3.1 Score: %.1f\n", cvss.BaseScore))
			b.WriteString(fmt.Sprintf("Severity: %s\n", cvss.BaseSeverity))
			b.WriteString(fmt.Sprintf("Attack Vector: %s\n", cvss.AttackVector))
			b.WriteString(fmt.Sprintf("Attack Complexity: %s\n", cvss.AttackComplexity))
			b.WriteString(fmt.Sprintf("Privileges Required: %s\n", cvss.PrivilegesRequired))
			b.WriteString(fmt.Sprintf("User Interaction: %s\n", cvss.UserInteraction))
			b.WriteString(fmt.Sprintf("Scope: %s\n", cvss.Scope))
		}

		if len(cve.References) > 0 {
			b.WriteString("References:\n")
			for _, ref := range cve.References {
				b.WriteString("  - " + ref.URL + " (" + ref.Source + ")\n")
			}
		}
	}

	return tools.Result{Output: b.String()}, nil
}

// exploitSearch provides Exploit-DB search
func exploitSearch(args map[string]string) (tools.Result, error) {
	query := args["query"]
	if query == "" {
		return tools.Result{}, fmt.Errorf("query is required")
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Exploit-DB Search Results for: %s\n\n", query))
	b.WriteString("To search locally, install Exploit-DB:\n")
	b.WriteString("  sudo apt update && sudo apt install exploitdb\n")
	b.WriteString("  searchsploit " + query + "\n\n")
	b.WriteString("Online search: https://www.exploit-db.com/search?q=" + netURL.QueryEscape(query))

	return tools.Result{Output: b.String()}, nil
}
