# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Mandatory Rules

- **English Only**: All code, comments, documentation, and commit messages MUST be in English
- **No Emoji**: Never use emoji in any file (code, docs, comments, commits)
- **No Local Paths**: Never expose local machine paths in code, tests, or documentation
- **No Backward Compatibility**: Breaking changes are acceptable. Prioritize optimal design and elegant code over backward compatibility. Do not deprecate, just remove or redesign

## Project Overview

**keychainbreaker** is a Go library for parsing and decrypting macOS Keychain files (`login.keychain-db`). It provides programmatic access to extract stored credentials from macOS Keychain database files.

The library uses only Go standard library (zero external dependencies).

## Modules and Go Versions

The repository holds two Go modules:

- **Library** (repository root, `github.com/moond4rk/keychainbreaker`): `go 1.20`. Consumers such as HackBrowserData build it with Go 1.20, so never raise the `go` directive, add a `toolchain` line, or use anything newer than Go 1.20 (`slices`, `maps`, `cmp`, `log/slog`, the `min`/`max`/`clear` builtins, range over int). Newer toolchains compile such code without complaint; only the Go 1.20 leg of CI catches it.
- **CLI** (`cmd/keychainbreaker`, its own `go.mod`): latest Go. It requires the published library version, and the release workflow moves that requirement forward.

## Build and Development Commands

```bash
go work init . ./cmd/keychainbreaker            # Once per clone: build the CLI against the local library (go.work is gitignored)
GOWORK=off go test -race ./...                  # Library tests
(cd cmd/keychainbreaker && go test -race ./...) # CLI tests, against the local library
golangci-lint run                               # Lint the library; run it in cmd/keychainbreaker for the CLI
golangci-lint fmt                               # Format (gofumpt + goimports)
```

## Release

Run the Release workflow with a version such as `v0.3.0`; `dry-run` tests and builds a snapshot without publishing. It tags the library on `main`, waits for the Go module proxy, and opens a `chore(release): <version>` pull request that points the CLI at the new library. Merging that pull request tags `cmd/keychainbreaker/<version>` on the merge commit and publishes the binaries and the Homebrew cask.

## Code Quality Standards

### Naming Conventions

- Exported types: PascalCase
- Internal types: camelCase
- Constants: camelCase for internal

### Testing Requirements

- Test with real keychain fixtures in `testdata/`
- Never hardcode local paths in tests

## Reference

- Related issue: https://github.com/moonD4rk/HackBrowserData/issues/519
