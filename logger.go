package keychainbreaker

// Logger receives the library's diagnostics; *slog.Logger satisfies it. The arguments after msg alternate keys and
// values, as in log/slog. Debug carries routine progress; Warn reports records that were skipped or not decrypted.
type Logger interface {
	Debug(msg string, args ...any)
	Warn(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Warn(string, ...any)  {}
