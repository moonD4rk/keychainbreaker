package keychainbreaker

// Logger is the interface for diagnostic logging within keychainbreaker.
// Implement this interface to receive verbose diagnostic messages from
// the library during parsing and unlock operations.
//
// The keysAndValues arguments are key-value pairs (e.g., "saltLen", 20).
//
// The default logger is silent (no-op). Use WithLogger to inject a
// custom implementation.
type Logger interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}
