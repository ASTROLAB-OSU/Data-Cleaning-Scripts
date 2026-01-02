package cleaning

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

// identifySequentialUsernames now returns a map of baseEmail -> set of numbers to remove
func identifySequentialNumbers(usernames []string, sequenceLimit int) map[string]map[int]bool {
	// baseEmail -> list of numbers found
	foundNumbers := make(map[string][]int)
	re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)

	for _, email := range usernames {
		matches := re.FindStringSubmatch(email)
		if matches != nil && len(matches) >= 4 {
			baseEmail := fmt.Sprintf("%s@%s", matches[1], matches[3])
			num, _ := strconv.Atoi(matches[2])
			foundNumbers[baseEmail] = append(foundNumbers[baseEmail], num)
		}
	}

	// This will hold only the numbers that are part of a 100+ sequence
	toRemove := make(map[string]map[int]bool)

	for base, nums := range foundNumbers {
		sort.Ints(nums)

		tempSeq := []int{}
		for i := 0; i < len(nums); i++ {
			if i > 0 && nums[i] == nums[i-1]+1 {
				tempSeq = append(tempSeq, nums[i])
			} else {
				// Sequence broke, check if the previous one was long enough
				if len(tempSeq) >= sequenceLimit {
					if toRemove[base] == nil {
						toRemove[base] = make(map[int]bool)
					}
					for _, n := range tempSeq {
						toRemove[base][n] = true
					}
				}
				tempSeq = []int{nums[i]} // Start new sequence
			}
		}
		// Final check for the last sequence in the slice
		if len(tempSeq) >= sequenceLimit {
			if toRemove[base] == nil {
				toRemove[base] = make(map[int]bool)
			}
			for _, n := range tempSeq {
				toRemove[base][n] = true
			}
		}
	}

	return toRemove
}

func RemoveSeqUsers(usernames, passwords []string, sequenceLimit int, removedSeqUsers *[]string) ([]string, []string) {
	// 1. Map of baseEmail -> Set of specific numbers to kill
	blacklist := identifySequentialNumbers(usernames, sequenceLimit)

	var newUsernames []string
	var newPasswords []string

	re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)

	for i := range usernames {
		email := usernames[i]
		password := passwords[i]
		credential := fmt.Sprintf("%s:%s", email, password)

		matches := re.FindStringSubmatch(email)

		// IF: It doesn't match the pattern (no numbers), it's safe.
		if matches == nil {
			newUsernames = append(newUsernames, email)
			newPasswords = append(newPasswords, password)
			continue
		}

		baseEmail := fmt.Sprintf("%s@%s", matches[1], matches[3])
		num, _ := strconv.Atoi(matches[2])

		// IF: The base exists in blacklist AND this specific number is flagged
		if numsToKill, exists := blacklist[baseEmail]; exists && numsToKill[num] {
			*removedSeqUsers = append(*removedSeqUsers, credential)
		} else {
			// Keep it
			newUsernames = append(newUsernames, email)
			newPasswords = append(newPasswords, password)
		}
	}
	return newUsernames, newPasswords
}
