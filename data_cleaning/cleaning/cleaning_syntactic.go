package cleaning

import (
	"Data-Cleaning/config"
	"fmt"
	"strings"
)

// RemoveRuleBased counts credentials that would be removed by rule-based filters
func RemoveSyntactic(usernames, passwords []string, removedSyntactic *[]string, filestats *config.CleaningStats, tldSet map[string]bool) ([]string, []string) {

	// Prepare output lists
	filteredUsernames := []string{}
	filteredPasswords := []string{}

	// Track duplicates
	duplicates := make(map[string]int)

	// Process each credential
	for i := range usernames {
		email := strings.ToLower(usernames[i])
		password := passwords[i]
		credential := fmt.Sprintf("%s:%s", email, password)
		shouldRemove := false

		// Check for duplicate credentials
		duplicates[credential]++
		if duplicates[credential] > 1 {
			filestats.Syn_DupeRemovals++
			shouldRemove = true
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			filestats.Syn_LenEmailRemovals++
			shouldRemove = true
		}

		// Validate email TLD
		result, _, _ := IsValidTLD(email, tldSet)
		if !result {
			filestats.Syn_TLDRemovals++
			shouldRemove = true
		}

		if shouldRemove {
			*removedSyntactic = append(*removedSyntactic, credential)
		} else {
			filteredUsernames = append(filteredUsernames, usernames[i])
			filteredPasswords = append(filteredPasswords, password)
		}
	}
	return filteredUsernames, filteredPasswords
}
