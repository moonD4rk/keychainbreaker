package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/moond4rk/keychainbreaker"
)

type cliLogger struct{}

func newCLILogger() keychainbreaker.Logger {
	return &cliLogger{}
}

func (*cliLogger) Debug(msg string, keysAndValues ...any) {
	fmt.Fprintf(os.Stderr, "[DEBUG] %-24s %s\n", msg, formatKV(keysAndValues))
}

func (*cliLogger) Info(msg string, keysAndValues ...any) {
	fmt.Fprintf(os.Stderr, "[INFO]  %-24s %s\n", msg, formatKV(keysAndValues))
}

func (*cliLogger) Warn(msg string, keysAndValues ...any) {
	fmt.Fprintf(os.Stderr, "[WARN]  %-24s %s\n", msg, formatKV(keysAndValues))
}

func (*cliLogger) Error(msg string, keysAndValues ...any) {
	fmt.Fprintf(os.Stderr, "[ERROR] %-24s %s\n", msg, formatKV(keysAndValues))
}

func formatKV(kv []any) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%v=%v", kv[i], kv[i+1])
	}
	return b.String()
}
