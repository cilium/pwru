package draw

import (
	"strings"

	"github.com/mattn/go-runewidth"
)

func repeatSafe(s string, n int) string {
	if n < 0 {
		return ""
	}
	return strings.Repeat(s, n)
}

func Line(w int, txt string) string {
	b := "│" 
	tw := runewidth.StringWidth(txt)
	return b + txt + repeatSafe(" ", w-2-tw) + b
}

func Break(w int) string {
	return "├" + repeatSafe("─", w-2) + "┤"
}

func Header(w int) string {
	return "┌" + repeatSafe("─", w-2) + "┐"
}

func Footer(w int) string {
	return "└" + repeatSafe("─", w-2) + "┘"
}
