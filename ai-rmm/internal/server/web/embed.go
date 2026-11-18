// Package web embeds the single-page operator dashboard.
package web

import _ "embed"

//go:embed index.html
var Index []byte
