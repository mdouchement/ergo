// Modified version of https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/pattern_matcher.go
//
// ISC License
//
// Copyright (c) 2018-2020
// Frank Denis <j at pureftpd dot org>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
package host

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/k-sone/critbitgo"
	"github.com/mdouchement/logger"
)

type PatternType int

const (
	PatternTypeNone PatternType = iota
	PatternTypePrefix
	PatternTypeSuffix
	PatternTypeSubstring
	PatternTypePattern
	PatternTypeExact
)

type PatternMatcher struct {
	log               logger.Logger
	blockedPrefixes   *critbitgo.Trie
	blockedSuffixes   *critbitgo.Trie
	blockedSubstrings []string
	blockedPatterns   []string
	blockedExact      map[string]interface{}
	indirectVals      map[string]interface{}
}

func NewPatternMatcher(log logger.Logger) *PatternMatcher {
	patternMatcher := PatternMatcher{
		blockedPrefixes: critbitgo.NewTrie(),
		blockedSuffixes: critbitgo.NewTrie(),
		blockedExact:    make(map[string]interface{}),
		indirectVals:    make(map[string]interface{}),
	}
	return &patternMatcher
}

func isGlobCandidate(str string) bool {
	for i, c := range str {
		if c == '?' || c == '[' {
			return true
		} else if c == '*' && i != 0 && i != len(str)-1 {
			return true
		}
	}
	return false
}

func (patternMatcher *PatternMatcher) Add(pattern string, val interface{}, position int) error {
	leadingStar := strings.HasPrefix(pattern, "*")
	trailingStar := strings.HasSuffix(pattern, "*")
	exact := strings.HasPrefix(pattern, "=")
	patternType := PatternTypeNone
	if isGlobCandidate(pattern) {
		patternType = PatternTypePattern
		_, err := filepath.Match(pattern, "example.com")
		if len(pattern) < 2 || err != nil {
			return fmt.Errorf("Syntax error in block rules at pattern %d", position)
		}
	} else if leadingStar && trailingStar {
		patternType = PatternTypeSubstring
		if len(pattern) < 3 {
			return fmt.Errorf("Syntax error in block rules at pattern %d", position)
		}
		pattern = pattern[1 : len(pattern)-1]
	} else if trailingStar {
		patternType = PatternTypePrefix
		if len(pattern) < 2 {
			return fmt.Errorf("Syntax error in block rules at pattern %d", position)
		}
		pattern = pattern[:len(pattern)-1]
	} else if exact {
		patternType = PatternTypeExact
		if len(pattern) < 2 {
			return fmt.Errorf("Syntax error in block rules at pattern %d", position)
		}
		pattern = pattern[1:]
	} else {
		patternType = PatternTypeSuffix
		if leadingStar {
			pattern = pattern[1:]
		}
		pattern = strings.TrimPrefix(pattern, ".")
	}
	if len(pattern) == 0 {
		patternMatcher.log.Errorf("Syntax error in block rule at line %d", position)
	}

	pattern = strings.ToLower(pattern)
	switch patternType {
	case PatternTypeSubstring:
		patternMatcher.blockedSubstrings = append(patternMatcher.blockedSubstrings, pattern)
		if val != nil {
			patternMatcher.indirectVals[pattern] = val
		}
	case PatternTypePattern:
		patternMatcher.blockedPatterns = append(patternMatcher.blockedPatterns, pattern)
		if val != nil {
			patternMatcher.indirectVals[pattern] = val
		}
	case PatternTypePrefix:
		patternMatcher.blockedPrefixes.Insert([]byte(pattern), val)
	case PatternTypeSuffix:
		patternMatcher.blockedSuffixes.Insert([]byte(StringReverse(pattern)), val)
	case PatternTypeExact:
		patternMatcher.blockedExact[pattern] = val
	default:
		patternMatcher.log.Fatal("Unexpected block type")
	}
	return nil
}

func (patternMatcher *PatternMatcher) Eval(qName string) (reject bool, reason string, val interface{}) {
	if len(qName) < 2 {
		return false, "", nil
	}

	revQname := StringReverse(qName)
	if match, xval, found := patternMatcher.blockedSuffixes.LongestPrefix([]byte(revQname)); found {
		if len(match) == len(revQname) || revQname[len(match)] == '.' {
			return true, "*." + StringReverse(string(match)), xval
		}
		if len(match) < len(revQname) && len(revQname) > 0 {
			if i := strings.LastIndex(revQname, "."); i > 0 {
				pName := revQname[:i]
				if match, _, found := patternMatcher.blockedSuffixes.LongestPrefix([]byte(pName)); found {
					if len(match) == len(pName) || pName[len(match)] == '.' {
						return true, "*." + StringReverse(string(match)), xval
					}
				}
			}
		}
	}

	if match, xval, found := patternMatcher.blockedPrefixes.LongestPrefix([]byte(qName)); found {
		return true, string(match) + "*", xval
	}

	for _, substring := range patternMatcher.blockedSubstrings {
		if strings.Contains(qName, substring) {
			return true, "*" + substring + "*", patternMatcher.indirectVals[substring]
		}
	}

	for _, pattern := range patternMatcher.blockedPatterns {
		if found, _ := filepath.Match(pattern, qName); found {
			return true, pattern, patternMatcher.indirectVals[pattern]
		}
	}

	if xval := patternMatcher.blockedExact[qName]; xval != nil {
		return true, qName, xval
	}

	return false, "", nil
}

func StringReverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
