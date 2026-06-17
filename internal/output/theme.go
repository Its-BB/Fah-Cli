package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	Header = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	Muted  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	Strong = lipgloss.NewStyle().Bold(true)
)

func KV(w io.Writer, key string, value any) {
	fmt.Fprintf(w, "%-22s %v\n", key, value)
}

func Table(w io.Writer, headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i := range headers {
			if i < len(row) && len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
	}
	printRow(w, headers, widths)
	sep := make([]string, len(headers))
	for i, width := range widths {
		sep[i] = strings.Repeat("-", width)
	}
	printRow(w, sep, widths)
	for _, row := range rows {
		printRow(w, row, widths)
	}
}

func printRow(w io.Writer, row []string, widths []int) {
	for i, width := range widths {
		cell := ""
		if i < len(row) {
			cell = row[i]
		}
		fmt.Fprintf(w, "%-*s", width, cell)
		if i < len(widths)-1 {
			fmt.Fprint(w, "  ")
		}
	}
	fmt.Fprintln(w)
}
