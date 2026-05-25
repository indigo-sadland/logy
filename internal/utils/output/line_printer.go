package output

import (
	"fmt"
	"strings"
)

var stdoutSupportsColor bool

const (
	colorReset  = "\033[0m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func Init(supportsColor bool) {
	stdoutSupportsColor = supportsColor
}
func Print(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if stdoutSupportsColor {
		fmt.Print(colorizePrintMessage(msg))
		return
	}
	fmt.Print(msg)
}

func colorizePrintMessage(msg string) string {
	switch {
	case strings.HasPrefix(msg, "[!]"):
		return colorYellow + colorBold + msg + colorReset
	case strings.HasPrefix(msg, "[+]"):
		return colorGreen + colorBold + msg + colorReset
	case strings.HasPrefix(msg, "[*]"):
		return colorBlue + msg + colorReset
	default:
		if strings.Contains(msg, "failed") {
			return colorRed + msg + colorReset
		}
		if strings.Contains(msg, "resolver/") || strings.Contains(msg, "discovery/") {
			return colorCyan + msg + colorReset
		}
		return msg
	}
}

/*func printToolSummary(statuses []discovery.ToolStatus) {
	if len(statuses) == 0 {
		return
	}
	Print("\n[*] discovery tool summary:\n")
	for _, status := range statuses {
		switch status.Status {
		case "failed":
			Print("[!]   %s -> failed (%s)\n", status.Name, status.Error)
		case "empty":
			Print("[!]   %s -> empty (0 results)\n", status.Name)
		default:
			Print("[+]   %s -> ok (%d results)\n", status.Name, status.RawResults)
		}
	}
}*/
