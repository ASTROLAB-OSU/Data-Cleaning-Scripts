package cleaning

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PasswordConfig holds the lists of passwords to check against.
// The RemoveSpecific map is designed for O(1) lookups.
type PasswordConfig struct {
	RemoveSpecific map[string]struct{}
	RemovePrefixes []string
}

// jsonConfig is a temporary struct used only for JSON unmarshaling.
type jsonConfig struct {
	Specific []string `json:"specific"`
	Prefixes []string `json:"prefixes"`
}

// LoadPasswordConfig reads the list of passwords from the specified JSON file path
// and prepares them for runtime use.
func loadPasswordConfig(filepath string) (*PasswordConfig, error) {
	// 1. Read the JSON file content
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// 2. Unmarshal into the temporary JSON struct
	var tempConfig jsonConfig
	if err := json.Unmarshal(data, &tempConfig); err != nil {
		return nil, err
	}

	// 3. Convert the specific list slice into a map for fast lookup
	specificMap := make(map[string]struct{}, len(tempConfig.Specific))
	for _, p := range tempConfig.Specific {
		specificMap[p] = struct{}{}
	}

	// 4. Return the final, runtime-optimized configuration
	return &PasswordConfig{
		RemoveSpecific: specificMap,
		RemovePrefixes: tempConfig.Prefixes,
	}, nil
}

// removeSuspiciousFollowOnDistrobution removes passwords manually verified to be botted by follow-on distribution.
// It accepts slices of usernames and passwords along with a pointer to a slice for removed entries.
// Returns new slices for usernames and passwords.
func RemoveSuspiciousFollowOnDistribution(usernames, passwords []string, removedFOD *[]string, configFile string) ([]string, []string) {
	config, err := loadPasswordConfig(configFile)
	if err != nil {
		fmt.Printf("Warning: could not load FOD config %s: %v\n", configFile, err)
		return usernames, passwords // nothing removed
	}

	var newUsernames []string
	var newPasswords []string

	// Process each password by its index.
	for i, pwd := range passwords {
		removePass := false

		// Check if the password exactly matches one in the specific set.
		if _, found := config.RemoveSpecific[pwd]; found {
			removePass = true
		}

		// Check if the password starts with any prefix in the all set.
		for _, prefix := range config.RemovePrefixes {
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
