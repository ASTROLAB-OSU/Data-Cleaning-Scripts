package cleaning

import (
	"fmt"
	"strings"
)

func IsValidTLD(email string, tldSet map[string]bool) (bool, string, string) {
	// Find @ symbol
	atIndex := strings.Index(email, "@")
	// Domain checks
	domain := email[atIndex+1:]
	// TLD check
	tldIdx := strings.LastIndex(domain, ".")
	if tldIdx < 0 {
		return false, email, "Domain Error: no tld"
	}
	tld := strings.ToLower(domain[tldIdx:])
	if !tldSet[tld] {
		return false, email, fmt.Sprintf("Domain Error: invalid tld %s", tld)
	}
	return true, email, "Valid Email"
}

// Helper functions
func isAlpha(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c rune) bool {
	return c >= '0' && c <= '9'
}
