package reporting

// Palette holds the RGB triples used by the branded PDF report. The values
// are byte-identical to the previous internal/web in-line palette so the
// generated artifact is unchanged.
type Palette struct {
	BG       [3]int
	Card     [3]int
	Muted    [3]int
	Border   [3]int
	FG       [3]int
	Subtle   [3]int
	Accent   [3]int
	Critical [3]int
	High     [3]int
	Medium   [3]int
	Low      [3]int
	Info     [3]int
	Code     [3]int
}

// ThemePalette returns the dark-theme palette baked into every Xalgorix
// report. The hex comments next to each color mirror the original
// reference values from internal/web/report.go.
func ThemePalette() Palette {
	return Palette{
		BG:       [3]int{5, 5, 5},       // #050505
		Card:     [3]int{10, 10, 10},    // #0a0a0a
		Muted:    [3]int{17, 17, 17},    // #111111
		Border:   [3]int{38, 38, 38},    // #262626
		FG:       [3]int{250, 250, 250}, // #fafafa
		Subtle:   [3]int{161, 161, 170}, // #a1a1aa
		Accent:   [3]int{16, 185, 129},  // #10b981
		Critical: [3]int{220, 38, 38},   // #dc2626
		High:     [3]int{234, 88, 12},   // #ea580c
		Medium:   [3]int{202, 138, 4},   // #ca8a04
		Low:      [3]int{37, 99, 235},   // #2563eb
		Info:     [3]int{82, 82, 82},    // #525252
		Code:     [3]int{23, 23, 23},    // #171717
	}
}
