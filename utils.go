package main

import (
	"errors"
	"regexp"

	"github.com/kolide/osquery-go/plugin/table"
)

// embed regexp.Regexp in a new type so we can extend it
type myRegexp struct {
	count int
	*regexp.Regexp
}

// add a new method to our new regular expression type
func (r *myRegexp) FindStringSubmatchMap(s string) map[string]string {
	captures := make(map[string]string)

	match := r.FindStringSubmatch(s)
	if match == nil {
		return captures
	}

	for i, name := range r.SubexpNames() {
		// Ignore the whole regexp match and unnamed groups
		if i == 0 || name == "" {
			continue
		}

		captures[name] = match[i]

	}
	return captures
}

func ListAddresses(queryContext table.QueryContext) ([]string, error) {
	results := []string{}
	if addrList, ok := queryContext.Constraints["addr"]; ok {
		for _, a := range addrList.Constraints {
			results = append(results, a.Expression)
		}
		return results, nil
	}
	return results, errors.New("Constraints does not have addr")
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
