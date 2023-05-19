package msglang

import "strings"

// ParseLang extracts the first language from a comma-separated list of languages.
func ParseLang(l string) string {
	langcode := strings.Split(l, ",")
	return strings.TrimSpace(langcode[0])
}
