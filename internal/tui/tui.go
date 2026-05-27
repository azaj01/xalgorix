// Package tui provides the interactive terminal UI using Bubbletea + Lipgloss.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xalgord/xalgorix/v4/internal/agent"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
	"github.com/xalgord/xalgorix/v4/internal/tools/reporting"
)

// ─── Color Palette ────────────────────────────────────────────────────────────

var (
	cyan       = lipgloss.Color("#06b6d4")
	cyanLight  = lipgloss.Color("#22d3ee")
	cyanBright = lipgloss.Color("#67e8f9")
	dimText    = lipgloss.Color("#525252")
	brightText = lipgloss.Color("#fafaf9")
	mutedText  = lipgloss.Color("#a3a3a3")
	red        = lipgloss.Color("#ef4444")
	orange     = lipgloss.Color("#ea580c")
	amber      = lipgloss.Color("#d97706")
	green      = lipgloss.Color("#22c55e")
	blue       = lipgloss.Color("#3b82f6")
)

// ─── Styles ───────────────────────────────────────────────────────────────────

var (
	bannerStyle = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	titleStyle  = lipgloss.NewStyle().Foreground(cyanLight).Bold(true)
	toolStyle   = lipgloss.NewStyle().Foreground(cyanBright)
	errorStyle  = lipgloss.NewStyle().Foreground(red)
	dimStyle    = lipgloss.NewStyle().Foreground(dimText)
	brightStyle = lipgloss.NewStyle().Foreground(brightText)
	statusStyle = lipgloss.NewStyle().Foreground(cyan).Bold(true)
	headerStyle = lipgloss.NewStyle().
			Foreground(brightText).
			Bold(true).
			Padding(0, 1).
			Background(lipgloss.Color("#0e3a4a"))
)

// ─── Banner ───────────────────────────────────────────────────────────────────

const Banner = `
 ██╗  ██╗ █████╗ ██╗      ██████╗  ██████╗ ██████╗ ██╗██╗  ██╗
 ╚██╗██╔╝██╔══██╗██║     ██╔════╝ ██╔═══██╗██╔══██╗██║╚██╗██╔╝
  ╚███╔╝ ███████║██║     ██║  ███╗██║   ██║██████╔╝██║ ╚███╔╝
  ██╔██╗ ██╔══██║██║     ██║   ██║██║   ██║██╔══██╗██║ ██╔██╗
 ██╔╝ ██╗██║  ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║██╔╝ ██╗
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝`

// ─── Messages ─────────────────────────────────────────────────────────────────

type agentEventMsg agent.Event
type tickMsg struct{}
type splashDoneMsg struct{}

// ─── Model ────────────────────────────────────────────────────────────────────

// Model is the Bubbletea model for the TUI.
type Model struct {
	cfg         *config.Config
	targets     []string
	instruction string
	width       int
	height      int

	// State
	showSplash   bool
	splashPhase  int
	chatLog      []string
	vulnCount    int
	toolCount    int
	iterCount    int
	agentRunning bool
	finished     bool

	// Agent
	events chan agent.Event
	ag     *agent.Agent
}

// NewModel creates a new TUI model.
func NewModel(cfg *config.Config, targets []string, instruction string) Model {
	return Model{
		cfg:         cfg,
		targets:     targets,
		instruction: instruction,
		showSplash:  true,
		chatLog:     []string{},
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tea.SetWindowTitle("Xalgorix"),
		tick(),
	)
}

func tick() tea.Cmd {
	return tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

// ─── Update ───────────────────────────────────────────────────────────────────

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "ctrl+q":
			if m.ag != nil {
				m.ag.Stop()
			}
			return m, tea.Quit
		case "esc":
			if m.ag != nil && m.agentRunning {
				m.ag.Stop()
				m.agentRunning = false
				m.chatLog = append(m.chatLog, errorStyle.Render("  ⛔ Agent stopped by user"))
			}
		}

	case tickMsg:
		if m.showSplash {
			m.splashPhase++
			if m.splashPhase > 40 { // ~2 seconds
				m.showSplash = false
				return m, tea.Batch(tick(), m.startAgent())
			}
			return m, tick()
		}

		// Poll for agent events
		if m.events != nil {
			for {
				select {
				case evt, ok := <-m.events:
					if !ok {
						m.events = nil
						break
					}
					m.handleEvent(evt)
				default:
					goto done
				}
			}
		done:
		}
		return m, tick()

	case splashDoneMsg:
		m.showSplash = false
		return m, m.startAgent()

	case agentEventMsg:
		m.handleEvent(agent.Event(msg))
		return m, nil
	}

	return m, nil
}

func (m *Model) startAgent() tea.Cmd {
	m.events = make(chan agent.Event, 512)
	// TUI runs without the dashboard listener, so the localGuard's
	// listener-port rule is dormant. Default BindAddr ("127.0.0.1") and
	// Port (0) keep loopback / RFC1918 / link-local rejection active.
	m.ag = agent.NewAgent(m.cfg, "XalgorixAgent", m.events, scopeguard.Config{BindAddr: "127.0.0.1", Port: 0})
	m.agentRunning = true

	m.chatLog = append(m.chatLog,
		titleStyle.Render("  ◈ Targets: ")+brightStyle.Render(strings.Join(m.targets, ", ")),
	)
	if m.instruction != "" {
		m.chatLog = append(m.chatLog,
			titleStyle.Render("  ◈ Instructions: ")+dimStyle.Render(m.instruction),
		)
	}
	m.chatLog = append(m.chatLog, "")

	go m.ag.Run(m.targets, m.instruction)
	return nil
}

func (m *Model) handleEvent(evt agent.Event) {
	switch evt.Type {
	case "thinking":
		m.iterCount++
		m.chatLog = append(m.chatLog,
			dimStyle.Render(fmt.Sprintf("  ◈ %s", evt.Content)),
		)

	case "tool_call":
		m.toolCount++
		icon := toolIcon(evt.ToolName)
		line := toolStyle.Render(fmt.Sprintf("  %s %s", icon, evt.ToolName))
		m.chatLog = append(m.chatLog, line)

		for k, v := range evt.ToolArgs {
			if len(v) > 100 {
				v = v[:100] + "..."
			}
			m.chatLog = append(m.chatLog,
				dimStyle.Render(fmt.Sprintf("     %s: %s", k, v)),
			)
		}

	case "tool_result":
		output := evt.ToolResult.Output
		if evt.ToolResult.Error != "" {
			output = "ERROR: " + evt.ToolResult.Error
			m.chatLog = append(m.chatLog, errorStyle.Render("     → "+truncStr(output, 200)))
		} else {
			m.chatLog = append(m.chatLog,
				dimStyle.Render("     → "+truncStr(output, 200)),
			)
		}
		// Real-time vuln display when report_vulnerability succeeds
		if evt.ToolName == "report_vulnerability" && evt.ToolResult.Error == "" {
			if vulnID, ok := metadataString(evt.ToolResult.Metadata, "vuln_id"); ok {
				vulns := reporting.GetVulnerabilities()
				if v, found := findReportedVulnerabilityByID(vulns, vulnID); found {
					m.vulnCount = len(vulns)
					icon := severityIcon(v.Severity)
					sev := severityStyle(v.Severity).Render(strings.ToUpper(v.Severity))
					m.chatLog = append(m.chatLog, "")
					m.chatLog = append(m.chatLog, titleStyle.Render(fmt.Sprintf("  🐛 VULNERABILITY FOUND — %s", icon)))
					m.chatLog = append(m.chatLog, fmt.Sprintf("     %s [%s] %s — %s", icon, v.ID, v.Title, sev))
				}
			}
		}
		m.chatLog = append(m.chatLog, "")

	case "message":
		// Streaming text — append to last line or start new
		cleaned := strings.TrimSpace(evt.Content)
		if cleaned != "" {
			m.chatLog = append(m.chatLog, brightStyle.Render("  "+cleaned))
		}

	case "error":
		m.chatLog = append(m.chatLog, errorStyle.Render("  ⚠ "+evt.Content))

	case "finished":
		m.agentRunning = false
		m.finished = true
		m.chatLog = append(m.chatLog, "")
		m.chatLog = append(m.chatLog, statusStyle.Render("  ✅ Agent finished: "+truncStr(evt.Content, 300)))

		// Show vulnerability summary
		vulns := reporting.GetVulnerabilities()
		m.vulnCount = len(vulns)
		if len(vulns) > 0 {
			m.chatLog = append(m.chatLog, "")
			m.chatLog = append(m.chatLog, titleStyle.Render(fmt.Sprintf("  ═══ Vulnerabilities Found: %d ═══", len(vulns))))
			for _, v := range vulns {
				icon := severityIcon(v.Severity)
				sev := severityStyle(v.Severity).Render(strings.ToUpper(v.Severity))
				m.chatLog = append(m.chatLog, fmt.Sprintf("  %s [%s] %s — %s", icon, v.ID, v.Title, sev))
			}
		}
	}

	// Keep log manageable
	if len(m.chatLog) > 500 {
		m.chatLog = m.chatLog[len(m.chatLog)-500:]
	}
}

// ─── View ─────────────────────────────────────────────────────────────────────

func (m Model) View() string {
	if m.width == 0 {
		return ""
	}

	if m.showSplash {
		return m.renderSplash()
	}

	return m.renderMain()
}

func (m Model) renderSplash() string {
	// Animated splash
	banner := bannerStyle.Render(Banner)

	welcome := brightStyle.Render("Welcome to ") + titleStyle.Render("Xalgorix") + brightStyle.Render("!")
	tagline := dimStyle.Render("Autonomous AI Pentesting Engine")

	// Animated "Starting..." text
	full := "Starting Xalgorix Agent"
	var animText strings.Builder
	for i, ch := range full {
		dist := abs(i - (m.splashPhase % (len(full) + 8)))
		switch {
		case dist <= 1:
			animText.WriteString(brightStyle.Render(string(ch)))
		case dist <= 3:
			animText.WriteString(lipgloss.NewStyle().Foreground(mutedText).Render(string(ch)))
		default:
			animText.WriteString(dimStyle.Render(string(ch)))
		}
	}

	content := lipgloss.JoinVertical(lipgloss.Center,
		banner,
		"",
		welcome,
		tagline,
		"",
		animText.String(),
		"",
		titleStyle.Render("xalgorix.io"),
	)

	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
}

func (m Model) renderMain() string {
	// Header bar
	header := headerStyle.Width(m.width).Render(
		fmt.Sprintf(" XALGORIX  │  Tools: %d  │  Vulns: %d  │  Iter: %d  │  %s",
			m.toolCount, m.vulnCount, m.iterCount, m.statusText()),
	)

	// Chat area
	chatHeight := m.height - 4 // header + footer
	if chatHeight < 5 {
		chatHeight = 5
	}

	var visible []string
	if len(m.chatLog) > chatHeight {
		visible = m.chatLog[len(m.chatLog)-chatHeight:]
	} else {
		visible = m.chatLog
	}

	chat := strings.Join(visible, "\n")
	// Pad to fill height
	lines := strings.Count(chat, "\n") + 1
	if lines < chatHeight {
		chat += strings.Repeat("\n", chatHeight-lines)
	}

	// Footer
	var footer string
	if m.finished {
		footer = dimStyle.Render(" Press Ctrl+C to exit")
	} else if m.agentRunning {
		footer = dimStyle.Render(" Press ESC to stop agent  │  Ctrl+C to quit")
	} else {
		footer = dimStyle.Render(" Press Ctrl+C to quit")
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		chat,
		footer,
	)
}

func (m Model) statusText() string {
	if m.finished {
		return statusStyle.Render("COMPLETED")
	}
	if m.agentRunning {
		return statusStyle.Render("RUNNING")
	}
	return dimStyle.Render("IDLE")
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func toolIcon(name string) string {
	switch {
	case strings.Contains(name, "terminal"):
		return "⚡"
	case strings.Contains(name, "browser"):
		return "🌐"
	case strings.Contains(name, "file") || strings.Contains(name, "str_replace") || strings.Contains(name, "list_files") || strings.Contains(name, "search_files"):
		return "📝"
	case strings.Contains(name, "request") || strings.Contains(name, "proxy"):
		return "🔗"
	case strings.Contains(name, "python"):
		return "🐍"
	case strings.Contains(name, "note"):
		return "📌"
	case strings.Contains(name, "report"):
		return "🐛"
	case strings.Contains(name, "finish"):
		return "✅"
	case strings.Contains(name, "search"):
		return "🔍"
	case strings.Contains(name, "agent"):
		return "🤖"
	default:
		return "🔧"
	}
}

func severityIcon(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "🔵"
	}
}

func severityStyle(sev string) lipgloss.Style {
	switch strings.ToLower(sev) {
	case "critical":
		return lipgloss.NewStyle().Foreground(red).Bold(true)
	case "high":
		return lipgloss.NewStyle().Foreground(orange).Bold(true)
	case "medium":
		return lipgloss.NewStyle().Foreground(amber).Bold(true)
	case "low":
		return lipgloss.NewStyle().Foreground(green)
	default:
		return lipgloss.NewStyle().Foreground(blue)
	}
}

func truncStr(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ─── CLI Fallback ─────────────────────────────────────────────────────────────

// SplashText builds the splash screen text for non-interactive mode.
func SplashText(version string) string {
	var b strings.Builder
	b.WriteString(Banner)
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("  Welcome to Xalgorix! v%s\n", version))
	b.WriteString("  Autonomous AI Pentesting Engine\n\n")
	return b.String()
}

// FormatEvent formats an agent event for CLI display.
func FormatEvent(evt agent.Event) string {
	switch evt.Type {
	case "thinking":
		return fmt.Sprintf("  ◈ %s\n", evt.Content)
	case "tool_call":
		icon := toolIcon(evt.ToolName)
		var b strings.Builder
		b.WriteString(fmt.Sprintf(" %s %s\n", icon, evt.ToolName))
		for k, v := range evt.ToolArgs {
			if len(v) > 120 {
				v = v[:120] + "..."
			}
			b.WriteString(fmt.Sprintf("   %s: %s\n", k, v))
		}
		return b.String()
	case "tool_result":
		output := evt.ToolResult.Output
		if evt.ToolResult.Error != "" {
			output = "ERROR: " + evt.ToolResult.Error
		}
		if len(output) > 500 {
			output = output[:500] + "..."
		}
		return fmt.Sprintf("   → %s\n", output)
	case "error":
		return fmt.Sprintf("  ⚠ Error: %s\n", evt.Content)
	case "finished":
		return fmt.Sprintf("\n  ✅ Agent finished: %s\n", evt.Content)
	default:
		return ""
	}
}

// FormatVulnSummary formats the final vulnerability summary.
func FormatVulnSummary() string {
	vulns := reporting.GetVulnerabilities()
	if len(vulns) == 0 {
		return "  No vulnerabilities found.\n"
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("\n  ═══ Vulnerabilities Found: %d ═══\n\n", len(vulns)))
	for _, v := range vulns {
		icon := severityIcon(v.Severity)
		b.WriteString(fmt.Sprintf("  %s [%s] %s — %s\n", icon, v.ID, v.Title, strings.ToUpper(v.Severity)))
		if v.Endpoint != "" {
			b.WriteString(fmt.Sprintf("     Endpoint: %s\n", v.Endpoint))
		}
		if v.CVSS > 0 {
			b.WriteString(fmt.Sprintf("     CVSS: %.1f\n", v.CVSS))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func metadataString(metadata map[string]any, key string) (string, bool) {
	if metadata == nil {
		return "", false
	}
	value, ok := metadata[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	text = strings.TrimSpace(text)
	return text, text != ""
}

func findReportedVulnerabilityByID(vulns []reporting.Vulnerability, id string) (reporting.Vulnerability, bool) {
	for _, vuln := range vulns {
		if vuln.ID == id {
			return vuln, true
		}
	}
	return reporting.Vulnerability{}, false
}

// RunInteractive starts the interactive Bubbletea TUI.
func RunInteractive(cfg *config.Config, targets []string, instruction string) error {
	m := NewModel(cfg, targets, instruction)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// RunCLI runs Xalgorix in non-interactive CLI mode.
func RunCLI(cfg *config.Config, targets []string, instruction string) {
	fmt.Print(SplashText("0.1.0"))
	fmt.Printf("  Targets: %s\n", strings.Join(targets, ", "))
	if instruction != "" {
		fmt.Printf("  Instructions: %s\n", instruction)
	}
	fmt.Println()

	events := make(chan agent.Event, 256)
	// CLI mode has no dashboard listener; localGuard defaults keep the
	// loopback / RFC1918 / link-local rejection active without firing
	// the listener-port rule.
	ag := agent.NewAgent(cfg, "XalgorixAgent", events, scopeguard.Config{BindAddr: "127.0.0.1", Port: 0})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for evt := range events {
			fmt.Print(FormatEvent(evt))
			if evt.Type == "finished" {
				return
			}
		}
	}()

	ag.Run(targets, instruction)
	close(events)
	<-done

	fmt.Print(FormatVulnSummary())
}
