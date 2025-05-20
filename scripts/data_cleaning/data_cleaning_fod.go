package main

import (
	"fmt"
	"strings"
)

// removeSuspiciousFollowOnDistrobution removes passwords manually verified to be botted by follow-on distribution.
// It accepts slices of usernames and passwords along with a pointer to a slice for removed entries.
// Returns new slices for usernames and passwords.
func removeSuspiciousFollowOnDistribution(usernames, passwords []string, removedFOD *[]string) ([]string, []string) {
	// Define the sets for specific passwords and prefixes.
	removePasswordsSpecific := map[string]struct{}{
		"010203kuk": {}, "0000000000o": {}, "1g2w3e4r": {}, "angelseye22": {},
		"motherlode": {}, "starwarsfan10": {}, "secret666": {}, "sophietorf": {},
		"Status": {}, "!~!1": {},
	}

	removePasswordsAll := []string{
		"111222t", "29rsavoy", "87654321 ", "asdasd5", "jennifer_", "jessica_", "lovely_",
		"marina_", "natasha_", "nikita_", "NULL", "paSSword", "$HEX", "tinkle",
		"target123", "victoria_", "valentina_", "vanessa_",
	}

	var newUsernames []string
	var newPasswords []string

	// Process each password by its index.
	for i, pwd := range passwords {
		removePass := false

		// Check if the password exactly matches one in the specific set.
		if _, found := removePasswordsSpecific[pwd]; found {
			removePass = true
		}

		// Check if the password starts with any prefix in the all set.
		for _, prefix := range removePasswordsAll {
			if strings.HasPrefix(pwd, prefix) {
				removePass = true
				break
			}
		}

		if !removePass {
			newUsernames = append(newUsernames, usernames[i])
			newPasswords = append(newPasswords, passwords[i])
		} else {
			*removedFOD = append(*removedFOD, fmt.Sprintf("%s:%s", usernames[i], pwd))
		}
	}

	return newUsernames, newPasswords
}
