package aws

import (
	"encoding/json"
	"strings"
)

// IsAdmin reports whether attached policies grant Allow * on * (no Condition, no NotAction).
// Permission boundaries, SCPs and session policies are not evaluated.
func IsAdmin(ps []Policy) (bool, string) {
	for _, p := range ps {
		if p.ARN == adminARN {
			return true, "AdministratorAccess is attached (attached policies only)"
		}
		if allowsAll(p.Document) {
			return true, "policy " + p.Name + " allows * on * (attached policies only)"
		}
	}
	return false, ""
}

type statement struct {
	Effect    string
	Action    stringList
	Resource  stringList
	NotAction json.RawMessage
	Condition json.RawMessage
}

// stringList accepts a JSON string or a list of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*l = []string{one}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(l))
}

func allowsAll(doc []byte) bool {
	if len(doc) == 0 {
		return false
	}
	var d struct{ Statement json.RawMessage }
	if json.Unmarshal(doc, &d) != nil {
		return false
	}
	var stmts []statement
	if json.Unmarshal(d.Statement, &stmts) != nil {
		var one statement
		if json.Unmarshal(d.Statement, &one) != nil {
			return false
		}
		stmts = []statement{one}
	}
	for _, s := range stmts {
		if strings.EqualFold(s.Effect, "Allow") && len(s.NotAction) == 0 && len(s.Condition) == 0 &&
			hasStar(s.Action) && hasStar(s.Resource) {
			return true
		}
	}
	return false
}

func hasStar(l stringList) bool { return contains(l, "*") }
