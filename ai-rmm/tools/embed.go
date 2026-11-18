// Package tools embeds the built-in tool library. Each *.ps1 file is one tool:
// a JSON header inside a <#RMM-TOOL ... #> comment, followed by the PowerShell
// body. See docs/WRITING-TOOLS.md.
package tools

import "embed"

//go:embed *.ps1
var FS embed.FS
