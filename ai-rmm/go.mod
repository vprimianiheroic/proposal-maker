module github.com/airmm/airmm

// Kept at 1.20 on purpose: the "legacy" agent build for Windows 7 SP1 /
// Server 2008 R2 / 2012 / 2012 R2 must compile with Go 1.20.x, the last Go
// release that supports those OS versions. Do not use stdlib APIs newer
// than Go 1.20 (slices, maps, log/slog, min/max builtins, "GET /path" mux
// patterns, ...).
go 1.20

require golang.org/x/sys v0.15.0
