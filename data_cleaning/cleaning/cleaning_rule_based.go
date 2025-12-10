package cleaning

import (
	"Data-Cleaning/config"
	"fmt"
	"strings"
)

// checkRuleBased counts credentials that would be removed by rule-based filters
func CheckRuleBased(usernames, passwords []string, removedRuleBased *[]string, filestats *config.CleaningStats, tldSet map[string]bool) {

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
			filestats.Rule_DupeRemovals++
			shouldRemove = true
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			filestats.Rule_LenEmailRemovals++
			shouldRemove = true
		}

		// Validate email TLD
		result, _, _ := IsValidTLD(email, tldSet)
		if !result {
			filestats.Rule_TLDRemovals++
			shouldRemove = true
		}

		if shouldRemove {
			*removedRuleBased = append(*removedRuleBased, credential)
			filestats.RuleBasedRemovals++
		}
	}
}

// removeRuleBased actually removes credentials based on rule-based filters
func RemoveRuleBased(usernames, passwords []string, removedRuleBased *[]string, filestats *config.CleaningStats, tldSet map[string]bool) ([]string, []string) {
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

		// Check for duplicate credentials
		duplicates[credential]++
		if duplicates[credential] > 1 {
			filestats.Rule_DupeRemovals++
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			filestats.Rule_LenEmailRemovals++
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Validate email TLD
		result, _, _ := IsValidTLD(email, tldSet)
		if !result {
			filestats.Rule_TLDRemovals++
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// If all checks pass, add to filtered lists
		filteredUsernames = append(filteredUsernames, usernames[i])
		filteredPasswords = append(filteredPasswords, password)
	}

	return filteredUsernames, filteredPasswords
}
