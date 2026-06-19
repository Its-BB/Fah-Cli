package tui

import tea "github.com/charmbracelet/bubbletea"

type Model struct {
	Message string
}

func (m Model) Init() tea.Cmd { return nil }
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}
func (m Model) View() string {
	if m.Message == "" {
		return "fahscan\n"
	}
	return m.Message + "\n"
}
