// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package tui is the interactive display for `cenziadah watch --tui`: a live,
// scrollable list of every scanned process marked SAFE or ALERT, with a detail
// view of the findings behind each verdict. It is only a display: the scanning
// loop lives in internal/watch and feeds this package through Sink. This is the
// only package that depends on the terminal UI libraries (bubbletea, lipgloss).
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
	"github.com/paulborile/cenziadah/internal/version"
)

// Messages from the watch loop (via Sink) to the model.
type (
	learningMsg struct{}
	learnedMsg  struct {
		identities, conflicts int
		res                   scan.Result
	}
	sweepMsg struct {
		n      int
		res    scan.Result
		events []model.Event
	}
	errMsg struct{ err error }
)

// Sink forwards watch-loop output into a running TUI program. It satisfies
// watch.Sink.
type Sink struct{ P *tea.Program }

func (s Sink) Learning() { s.P.Send(learningMsg{}) }
func (s Sink) Learned(set *baseline.Set, res scan.Result) {
	s.P.Send(learnedMsg{identities: set.Len(), conflicts: set.Conflicts, res: res})
}
func (s Sink) Sweep(n int, res scan.Result, ev []model.Event) {
	s.P.Send(sweepMsg{n: n, res: res, events: ev})
}
func (s Sink) Error(err error) { s.P.Send(errMsg{err}) }

// Fatal shows an error that ended the watch loop; the user quits with q.
func Fatal(p *tea.Program, err error) { p.Send(errMsg{fmt.Errorf("watch stopped: %w", err)}) }

// NewProgram builds the TUI. A receive on rescan asks the loop for an immediate
// sweep; sends are non-blocking, so a busy loop never freezes the UI.
//
// bubbletea's own SIGINT/SIGTERM handler is disabled: the caller owns signals
// and calls Quit. With both installed, the caller's Quit can end the event loop
// first, and bubbletea's handler then blocks forever delivering its interrupt,
// hanging shutdown. (Ctrl+C inside the TUI is a key press, handled by the model.)
func NewProgram(rescan chan<- struct{}, interval time.Duration) *tea.Program {
	return tea.NewProgram(newModel(rescan, interval), tea.WithAltScreen(), tea.WithoutSignalHandler())
}

// recentEvents is how many recent changes the footer keeps.
const recentEvents = 5

// maxHistory bounds the history view (memory budget): oldest events are dropped.
const maxHistory = 2000

// stickyAlert is an alert that fired (NEW, above INFO). It is kept after the
// finding resolves (a short-lived child exited, a webshell ran one command) until
// the operator acknowledges it, so nothing that alerted can vanish unseen.
// Acknowledging only clears this display state; detection is unaffected.
type stickyAlert struct {
	f        model.Finding
	first    time.Time
	resolved time.Time // zero while still active
}

type stickyProc struct {
	target model.TargetDesc
	alerts []*stickyAlert
}

func (st *stickyProc) worst() model.Severity {
	w := model.SevInfo
	for _, a := range st.alerts {
		if a.f.Severity > w {
			w = a.f.Severity
		}
	}
	return w
}

func stickyKey(f model.Finding) string {
	return string(f.Technique) + "\x00" + f.Title + "\x00" + f.Detail
}

type row struct {
	rep        model.Report // for a skipped process only Target is set
	active     int
	suppressed int
	worst      model.Severity
	skip       string // non-empty: the process was not inspected, and why
	base       model.BaselineState
	sticky     *stickyProc // unacknowledged earlier alerts, or nil
	gone       bool        // process exited; the row exists only for its sticky alerts
}

// alertAt is the lowest severity that makes a row ALERT (and a sticky WAS!).
// LOW and INFO findings are recorded (FINDINGS count, history, log) but are not
// alerts: e.g. a package-installed program a service had not started before.
const alertAt = model.SevMedium

func (r row) alert() bool { return r.active > 0 && r.worst >= alertAt }

// rank orders rows: alerts, then unacknowledged earlier alerts (WAS!), then
// safe, then skipped.
func (r row) rank() int {
	switch {
	case r.alert():
		return 0
	case r.sticky != nil:
		return 1
	case r.skip == "":
		return 2
	default:
		return 3
	}
}

// sortSeverity is the severity rows of the same rank are ordered by.
func (r row) sortSeverity() model.Severity {
	if r.alert() {
		return r.worst
	}
	if r.sticky != nil {
		return r.sticky.worst()
	}
	return model.SevInfo
}

type state struct {
	rescan   chan<- struct{}
	interval time.Duration

	rows        []row
	alertsOnly  bool
	showSkipped bool
	cursor      int // index into visible()
	offset      int // first visible row in the list window
	detail      bool
	detailOff   int
	history     bool // history view
	historyOff  int
	width       int
	height      int

	phase   string // "learning", "watching"
	sweep   int
	last    time.Time
	stats   scan.Stats
	skipped int
	took    time.Duration
	errText string
	recent  []model.Event
	// accepted holds, per pid, findings already present when the baseline was
	// learned (and therefore not alerted on). Shown in the detail view.
	accepted map[int][]model.Finding
	nAccept  int
	nNew     int // programs auto-learned after start

	sticky  map[int]*stickyProc // by pid
	events  []model.Event       // history, oldest first, bounded by maxHistory
	lastRes scan.Result         // to rebuild rows after an acknowledge
}

func newModel(rescan chan<- struct{}, interval time.Duration) *state {
	return &state{rescan: rescan, interval: interval, phase: "starting", width: 100, height: 30,
		sticky: map[int]*stickyProc{}}
}

func (m *state) Init() tea.Cmd { return nil }

func (m *state) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case learningMsg:
		m.phase = "learning baseline"
	case learnedMsg:
		m.phase = "watching"
		m.accepted = map[int][]model.Finding{}
		m.addLearned(msg.res)
		m.setResult(msg.res)
	case sweepMsg:
		m.sweep = msg.n
		m.errText = ""
		m.addLearned(msg.res)
		m.addEvents(msg.events) // before setResult: rows show this sweep's sticky alerts
		m.setResult(msg.res)
	case errMsg:
		m.errText = msg.err.Error()
	case tea.KeyMsg:
		return m, m.key(msg.String())
	}
	return m, nil
}

func (m *state) key(k string) tea.Cmd {
	switch k {
	case "q", "ctrl+c":
		return tea.Quit
	case "r":
		select {
		case m.rescan <- struct{}{}:
		default: // a sweep is already running
		}
		return nil
	}
	if m.history {
		switch k {
		case "esc", "h", "left", "backspace":
			m.history = false
		case "up", "k":
			m.historyOff--
		case "down", "j":
			m.historyOff++
		case "pgup":
			m.historyOff -= m.height - 3
		case "pgdown":
			m.historyOff += m.height - 3
		case "home", "g":
			m.historyOff = 0
		case "end", "G":
			m.historyOff = len(m.events) - 1
		}
		if m.historyOff > len(m.events)-1 {
			m.historyOff = len(m.events) - 1
		}
		if m.historyOff < 0 {
			m.historyOff = 0
		}
		return nil
	}
	if m.detail {
		switch k {
		case "c":
			m.acknowledge(false)
		case "esc", "left", "backspace":
			m.detail = false
		case "up", "k":
			if m.detailOff > 0 {
				m.detailOff--
			}
		case "down", "j":
			m.detailOff++
		}
		return nil
	}
	n := len(m.visible())
	switch k {
	case "up", "k":
		m.cursor--
	case "down", "j":
		m.cursor++
	case "pgup":
		m.cursor -= m.listHeight()
	case "pgdown":
		m.cursor += m.listHeight()
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = n - 1
	case "a":
		m.alertsOnly = !m.alertsOnly
		m.cursor, m.offset = 0, 0
	case "s":
		m.showSkipped = !m.showSkipped
		m.cursor, m.offset = 0, 0
	case "enter", "l", "right":
		if n > 0 {
			m.detail, m.detailOff = true, 0
		}
	case "h":
		m.history, m.historyOff = true, 0
	case "c":
		m.acknowledge(false)
	case "C":
		m.acknowledge(true)
	}
	m.clamp()
	return nil
}

// acknowledge clears the earlier-alert marker of the selected row (or of all
// rows): the operator has seen them. Display state only.
func (m *state) acknowledge(all bool) {
	if all {
		m.sticky = map[int]*stickyProc{}
	} else if v := m.visible(); m.cursor < len(v) {
		delete(m.sticky, v[m.cursor].rep.Target.PID)
	}
	m.setResult(m.lastRes)
	if m.detail {
		if v := m.visible(); m.cursor >= len(v) || v[m.cursor].gone {
			m.detail = false // an exited process's row is gone once acknowledged
		}
	}
}

// setResult rebuilds the rows, alerts first (worst severity first), then by pid,
// keeping the cursor on the same pid when it is still present.
func (m *state) setResult(res scan.Result) {
	keep := -1
	if v := m.visible(); m.cursor < len(v) && len(v) > 0 {
		keep = v[m.cursor].rep.Target.PID
	}
	m.lastRes = res
	m.rows = m.rows[:0]
	present := map[int]bool{}
	for _, rep := range res.Reports {
		r := row{rep: rep, worst: rep.MaxSeverity(), base: rep.Baseline}
		if st := m.sticky[rep.Target.PID]; st != nil && sameProcess(st.target, rep.Target) {
			r.sticky = st
			present[rep.Target.PID] = true
		}
		for _, f := range rep.Findings {
			if f.Suppressed {
				r.suppressed++
			} else {
				r.active++
			}
		}
		m.rows = append(m.rows, r)
	}
	for pid, st := range m.sticky {
		if !present[pid] {
			// Exited (or pid reused): keep its alerts visible until acknowledged.
			m.rows = append(m.rows, row{rep: model.Report{Target: st.target}, sticky: st, gone: true})
		}
	}
	for _, sk := range res.Skipped {
		if sk.Reason == scan.ReasonKernel || sk.Reason == scan.ReasonSelf {
			continue // nothing to inspect there; not worth a row
		}
		if _, ok := m.sticky[sk.PID]; ok {
			continue // shown as its earlier-alert row instead
		}
		m.rows = append(m.rows, row{rep: model.Report{Target: model.TargetDesc{PID: sk.PID, Name: sk.Name, Exe: sk.Exe}},
			skip: sk.Reason, base: sk.Baseline})
	}
	sort.SliceStable(m.rows, func(i, j int) bool {
		a, b := m.rows[i], m.rows[j]
		if a.rank() != b.rank() {
			return a.rank() < b.rank()
		}
		if as, bs := a.sortSeverity(), b.sortSeverity(); as != bs {
			return as > bs
		}
		return a.rep.Target.PID < b.rep.Target.PID
	})
	m.stats, m.skipped, m.last = res.Stats, len(res.Skipped), res.FinishedAt
	m.took = res.FinishedAt.Sub(res.StartedAt)
	if keep >= 0 {
		for i, r := range m.visible() {
			if r.rep.Target.PID == keep {
				m.cursor = i
			}
		}
	}
	m.clamp()
}

// addLearned records findings accepted while learning (at start, or when a new
// trusted program is auto-learned) and announces auto-learned programs.
func (m *state) addLearned(res scan.Result) {
	if m.accepted == nil {
		m.accepted = map[int][]model.Finding{}
	}
	for _, e := range res.Accepted {
		m.accepted[e.Target.PID] = append(m.accepted[e.Target.PID], e.Finding)
	}
	m.nAccept += len(res.Accepted)
	m.nNew += len(res.NewPrograms)
	m.addEvents(res.Accepted)
	for _, t := range res.NewPrograms {
		m.addEvents([]model.Event{{Kind: model.EventLearned, At: res.FinishedAt, Target: t}}) // no finding: "new program"
	}
}

// addEvents feeds the footer, the history and the sticky alerts.
func (m *state) addEvents(ev []model.Event) {
	m.recent = append(m.recent, ev...)
	if len(m.recent) > recentEvents {
		m.recent = m.recent[len(m.recent)-recentEvents:]
	}
	m.events = append(m.events, ev...)
	if len(m.events) > maxHistory {
		m.events = m.events[len(m.events)-maxHistory:]
	}
	for _, e := range ev {
		switch {
		case e.Kind == model.EventNew && e.Finding.Severity >= alertAt:
			m.stick(e)
		case e.Kind == model.EventResolved:
			if st := m.sticky[e.Target.PID]; st != nil {
				for _, a := range st.alerts {
					if stickyKey(a.f) == stickyKey(e.Finding) && a.resolved.IsZero() {
						a.resolved = e.At
					}
				}
			}
		}
	}
}

func (m *state) stick(e model.Event) {
	st := m.sticky[e.Target.PID]
	if st == nil || !sameProcess(st.target, e.Target) {
		st = &stickyProc{target: e.Target}
		m.sticky[e.Target.PID] = st
	}
	for _, a := range st.alerts {
		if stickyKey(a.f) == stickyKey(e.Finding) {
			a.resolved = time.Time{} // fired again
			return
		}
	}
	st.alerts = append(st.alerts, &stickyAlert{f: e.Finding, first: e.At})
}

// sameProcess tells a pid's original process from a later one reusing the pid.
func sameProcess(a, b model.TargetDesc) bool {
	return a.StartsAt == 0 || b.StartsAt == 0 || a.StartsAt == b.StartsAt
}

func (m *state) visible() []row {
	var out []row
	for _, r := range m.rows {
		switch {
		case m.alertsOnly && !r.alert() && r.sticky == nil:
		case !m.showSkipped && r.skip != "":
		default:
			out = append(out, r)
		}
	}
	return out
}

// baseCounts renders how the scanned processes split by baseline state, e.g.
// "240 checked · 3 new · 2 none".
func (m *state) baseCounts() string {
	n := map[model.BaselineState]int{}
	for _, r := range m.rows {
		if r.skip == "" {
			n[r.base]++
		}
	}
	var parts []string
	for _, b := range []model.BaselineState{model.BaselineChecked, model.BaselineNew, model.BaselineNone} {
		if n[b] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[b], b))
		}
	}
	return strings.Join(parts, " · ")
}

func orDash(b model.BaselineState) string {
	if b == "" {
		return "-"
	}
	return string(b)
}

func (m *state) alerts() int {
	n := 0
	for _, r := range m.rows {
		if r.alert() {
			n++
		}
	}
	return n
}

func (m *state) listHeight() int {
	h := m.height - 4 - recentEvents - 1 // header, column titles, footer, events
	if h < 3 {
		h = 3
	}
	return h
}

func (m *state) clamp() {
	n := len(m.visible())
	if m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	h := m.listHeight()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+h {
		m.offset = m.cursor - h + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

var (
	styleHeader = lipgloss.NewStyle().Bold(true).Reverse(true)
	styleAlert  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	styleSafe   = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleDim    = lipgloss.NewStyle().Faint(true)
	styleCursor = lipgloss.NewStyle().Reverse(true)
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	styleNew    = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))            // cyan
	styleNone   = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))            // yellow
	styleWas    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("13")) // magenta
)

// baseCell renders the BASE column (8 wide). The verdict colours (SAFE/ALERT)
// say what was found; this says how much that verdict is worth.
func baseCell(b model.BaselineState) string {
	cell := fmt.Sprintf("%-8s", b)
	switch b {
	case model.BaselineNew:
		return styleNew.Render(cell)
	case model.BaselineNone:
		return styleNone.Render(cell)
	case model.BaselineKnown:
		return styleDim.Render(cell)
	case "":
		return "-       "
	}
	return cell
}

// baseExplain is the detail-view sentence for a baseline state.
func baseExplain(b model.BaselineState) string {
	switch b {
	case model.BaselineChecked:
		return "compared with the baseline learned in an earlier sweep: the verdict is a real one"
	case model.BaselineNew:
		return "baseline learned in this sweep (start, or new package-installed program): SAFE means nothing yet, the first real check is the next sweep"
	case model.BaselineNone:
		return "no baseline (program not running at start and not package-installed): only checks that need no reference ran"
	case model.BaselineKnown:
		return "not inspected yet (too young); its program already has a baseline, so it will be checked against it"
	}
	return ""
}

func (m *state) View() string {
	var b strings.Builder
	b.WriteString(styleHeader.Width(m.width).Render(m.headerLine()))
	b.WriteString("\n")
	switch {
	case m.history:
		m.viewHistory(&b)
	case m.detail:
		m.viewDetail(&b)
	default:
		m.viewList(&b)
	}
	return b.String()
}

func (m *state) headerLine() string {
	s := fmt.Sprintf(" cenziadah %s watch | %s", version.Version, m.phase)
	if m.sweep > 0 {
		s += fmt.Sprintf(" | sweep %d at %s", m.sweep, m.last.Format("15:04:05"))
	}
	if m.took > 0 {
		s += fmt.Sprintf(" (took %s)", m.took.Round(100*time.Millisecond))
	}
	s += fmt.Sprintf(" | %d scanned", m.stats.Scanned)
	if bc := m.baseCounts(); bc != "" {
		s += " (" + bc + ")"
	}
	s += fmt.Sprintf(", %d alert, %d skipped | every %s", m.alerts(), m.skipped, m.interval)
	if m.nAccept > 0 {
		s += fmt.Sprintf(" | %d accepted at learn", m.nAccept)
	}
	if m.nNew > 0 {
		s += fmt.Sprintf(" | %d new programs learned", m.nNew)
	}
	if n := len(m.sticky); n > 0 {
		s += fmt.Sprintf(" | %d unacknowledged", n)
	}
	return s
}

func (m *state) viewList(b *strings.Builder) {
	fmt.Fprintf(b, "%-8s %-16s %-6s %-8s %-9s %-8s %s\n", "PID", "NAME", "STATUS", "BASE", "WORST", "FINDINGS", "EXE")
	vis := m.visible()
	h := m.listHeight()
	for i := m.offset; i < len(vis) && i < m.offset+h; i++ {
		r := vis[i]
		status, worst := styleSafe.Render("SAFE  "), "-        "
		if r.alert() {
			status, worst = styleAlert.Render("ALERT "), fmt.Sprintf("%-9s", r.worst)
		} else if r.sticky != nil {
			status, worst = styleWas.Render("WAS!  "), fmt.Sprintf("%-9s", r.sticky.worst())
		}
		if r.gone {
			line := fmt.Sprintf("%-8d %-16s %s %-8s %s %-8s %s", r.rep.Target.PID, clip(r.rep.Target.Name, 16),
				status, "-", worst, "-", clip("(exited) "+r.rep.Target.Exe, m.width-61))
			if i == m.cursor {
				line = styleCursor.Render(line)
			}
			b.WriteString(line + "\n")
			continue
		}
		if r.skip != "" {
			status := "SKIP  "
			if r.skip == scan.ReasonTooYoung {
				status = "WAIT  "
			}
			line := fmt.Sprintf("%-8d %-16s %s %-8s %-9s %-8s %s", r.rep.Target.PID, clip(r.rep.Target.Name, 16),
				status, orDash(r.base), "-", "-", clip(r.skip+" · "+r.rep.Target.Exe, m.width-61))
			if i == m.cursor {
				line = styleCursor.Render(line)
			} else {
				line = styleDim.Render(line)
			}
			b.WriteString(line + "\n")
			continue
		}
		mark := " "
		if r.rep.Degraded != "" {
			mark = "~" // checked without module integrity
		}
		base := baseCell(r.base)
		if i == m.cursor {
			base = fmt.Sprintf("%-8s", orDash(r.base)) // plain inside the reversed cursor bar
		}
		line := fmt.Sprintf("%-8d %-16s %s %s %s %-8s %s", r.rep.Target.PID, clip(r.rep.Target.Name, 16),
			status, base, worst, fmt.Sprintf("%d%s", r.active, mark), clip(r.rep.Target.Exe, m.width-61))
		if i == m.cursor {
			line = styleCursor.Render(line)
		}
		b.WriteString(line + "\n")
	}
	for i := len(vis) - m.offset; i < h; i++ {
		b.WriteString("\n")
	}
	if m.errText != "" {
		b.WriteString(styleErr.Render(clip(m.errText, m.width)) + "\n")
	} else {
		b.WriteString(styleDim.Render("recent changes:") + "\n")
	}
	for i := 0; i < recentEvents; i++ {
		if i < len(m.recent) {
			b.WriteString(clip(" "+eventLine(m.recent[len(m.recent)-1-i], "15:04:05"), m.width))
		}
		b.WriteString("\n")
	}
	filter, skipped := "all", "hidden"
	if m.alertsOnly {
		filter = "alerts only"
	}
	if m.showSkipped {
		skipped = "shown"
	}
	b.WriteString(styleDim.Render(fmt.Sprintf("↑/↓ move  enter details  h history  c/C acknowledge  a filter (%s)  s skipped (%s)  r rescan  q quit  ~=no memory  ", filter, skipped)))
	b.WriteString(styleWas.Render("WAS!") + styleDim.Render("=alerted earlier  ") + styleNew.Render("new") + styleDim.Render("=learned this sweep  ") + styleNone.Render("none") + styleDim.Render("=no baseline"))
}

// eventLine renders one event on a single line, with the finding's detail (which
// child, which mapping), e.g.
// "14:12:18 NEW      HIGH     pid=1384 apache2 proctree.unexpected_child | pid=... exe=/bin/sh cmd=..."
func eventLine(e model.Event, timeFmt string) string {
	what := fmt.Sprintf("%-8s %s", e.Finding.Severity, e.Finding.Technique)
	if e.Finding.Technique == "" {
		what = "new program " + e.Target.Exe
	} else if e.Finding.Detail != "" {
		what += " | " + e.Finding.Detail
	}
	return fmt.Sprintf("%s %-8s pid=%d %s %s", e.At.Format(timeFmt), strings.ToUpper(string(e.Kind)), e.Target.PID, e.Target.Name, what)
}

// viewHistory lists every event since start (bounded by maxHistory), newest
// first, with full details.
func (m *state) viewHistory(b *strings.Builder) {
	fmt.Fprintf(b, "history: %d event(s), newest first\n", len(m.events))
	h := m.height - 3
	for i := m.historyOff; i < len(m.events) && i < m.historyOff+h; i++ {
		e := m.events[len(m.events)-1-i]
		txt := clip(eventLine(e, "01-02 15:04:05"), m.width)
		switch {
		case e.Kind == model.EventNew && e.Finding.Severity >= alertAt:
			txt = styleAlert.Render(txt)
		case e.Kind == model.EventResolved || e.Kind == model.EventLearned:
			txt = styleDim.Render(txt)
		}
		b.WriteString(txt + "\n")
	}
	b.WriteString(styleDim.Render("↑/↓ pgup/pgdn scroll  esc back  q quit"))
}

func (m *state) viewDetail(b *strings.Builder) {
	vis := m.visible()
	if m.cursor >= len(vis) {
		m.detail = false
		m.viewList(b)
		return
	}
	r := vis[m.cursor]
	t := r.rep.Target
	type line struct {
		text  string
		style *lipgloss.Style
	}
	var lines []line
	// add takes PLAIN text (sanitized and clipped at render time) and an optional
	// style, so attacker-controlled strings never reach the terminal raw.
	add := func(st *lipgloss.Style, format string, a ...any) {
		lines = append(lines, line{fmt.Sprintf(format, a...), st})
	}
	add(nil, "pid %d  %s  uid %d", t.PID, t.Name, t.UID)
	add(nil, "exe      %s", t.Exe)
	add(nil, "build-id %s", t.BuildID)
	add(nil, "cmdline  %s", t.Cmdline)
	add(nil, "identity %s", scan.Identity(t))
	if why := baseExplain(r.base); why != "" {
		st := (*lipgloss.Style)(nil)
		switch r.base {
		case model.BaselineNew:
			st = &styleNew
		case model.BaselineNone:
			st = &styleNone
		}
		add(st, "baseline %s: %s", r.base, why)
	}
	if r.gone {
		add(nil, "")
		add(&styleErr, "process has exited; shown only for its unacknowledged alerts")
	}
	if r.sticky != nil {
		add(nil, "")
		add(&styleWas, "earlier alerts, not acknowledged (c acknowledges):")
		for _, a := range r.sticky.alerts {
			when := "first " + a.first.Format("15:04:05") + ", still active"
			if !a.resolved.IsZero() {
				when = "first " + a.first.Format("15:04:05") + ", resolved " + a.resolved.Format("15:04:05")
			}
			add(nil, "  [%s] %s (%s), %s", a.f.Severity, a.f.Title, a.f.Technique, when)
			if a.f.Detail != "" {
				add(nil, "      %s", a.f.Detail)
			}
		}
	}
	if r.skip != "" {
		add(nil, "")
		add(&styleErr, "NOT INSPECTED: %s", r.skip)
		switch r.skip {
		case scan.ReasonPermission:
			add(nil, "cenziadah cannot read this process: run watch as root (or with CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH).")
		case scan.ReasonTooYoung:
			add(nil, "It started less than --min-age ago; it is inspected on the next sweep if it is still running.")
		}
	}
	if r.rep.Degraded != "" {
		add(&styleErr, "degraded: %s", r.rep.Degraded)
	}
	add(nil, "")
	switch {
	case r.skip != "", r.gone:
	case r.active == 0:
		add(&styleSafe, "SAFE: no active findings")
	case !r.alert():
		add(&styleSafe, "SAFE: %d low-severity finding(s) recorded (below the alert threshold)", r.active)
	default:
		add(&styleAlert, "ALERT: %d active finding(s)", r.active)
	}
	for _, f := range sortedFindings(r.rep.Findings, false) {
		add(nil, "  [%s] %s (%s)", f.Severity, f.Title, f.Technique)
		if f.Detail != "" {
			add(nil, "      %s", f.Detail)
		}
	}
	if acc := m.accepted[t.PID]; len(acc) > 0 && r.skip == "" {
		add(nil, "")
		add(&styleErr, "%d finding(s) already present when the baseline was learned (accepted, not alerted):", len(acc))
		for _, f := range acc {
			add(nil, "  [%s] %s (%s) %s", f.Severity, f.Title, f.Technique, f.Detail)
		}
	}
	if r.suppressed > 0 {
		add(nil, "")
		add(&styleDim, "%d suppressed as known-good:", r.suppressed)
		for _, f := range sortedFindings(r.rep.Findings, true) {
			add(&styleDim, "  %s: %s (%s)", f.Technique, f.Detail, f.SuppressReason)
		}
	}

	h := m.height - 2
	if m.detailOff > len(lines)-1 {
		m.detailOff = len(lines) - 1
	}
	for i := m.detailOff; i < len(lines) && i < m.detailOff+h; i++ {
		txt := clip(lines[i].text, m.width)
		if lines[i].style != nil {
			txt = lines[i].style.Render(txt)
		}
		b.WriteString(txt + "\n")
	}
	b.WriteString(styleDim.Render("↑/↓ scroll  esc back  c acknowledge  r rescan  q quit"))
}

func sortedFindings(fs []model.Finding, suppressed bool) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Suppressed == suppressed {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// clip shortens s to n runes and strips control characters (process names and
// cmdlines are attacker-influenced and must not drive the terminal).
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
	if n <= 0 {
		return ""
	}
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
