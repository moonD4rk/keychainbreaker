# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Mandatory Rules

- **English Only**: All code, comments, documentation, and commit messages MUST be in English
- **No Emoji**: Never use emoji in any file (code, docs, comments, commits)
- **No Local Paths**: Never expose local machine paths in code, tests, or documentation
- **No Backward Compatibility**: Breaking changes are acceptable. Prioritize optimal design and elegant code over backward compatibility. Do not deprecate, just remove or redesign

## Project Overview

**go-chainbreaker** is a Go library for parsing and decrypting macOS Keychain files (`login.keychain-db`). It provides programmatic access to extract stored credentials from macOS Keychain database files.

The library uses only Go standard library (zero external dependencies).

## Build and Development Commands

```bash
go test ./...                              # Run all tests
go test -v -race ./...                     # Run tests with race detection
go test -cover ./...                       # Run tests with coverage
golangci-lint run                          # Run linter
gofumpt -l -w .                            # Format (stricter than gofmt)
goimports -w -local github.com/moond4rk/go-chainbreaker . # Format imports
go build ./...                             # Build
```

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
