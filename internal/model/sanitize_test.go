package model

import "testing"

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"prod":           "prod",
		"pr\x1b[31mod":   "pr?[31mod",
		"a‮b":            "a?b",
		"a\u2066b\u2069": "a?b?",
		"tab\there":      "tab?here",
		"l1\nl2":         "l1?l2",
		"lrm\u200e rlm\u200f alm\u061c ls\u2028 ps\u2029": "lrm? rlm? alm? ls? ps?",
		"del\x7fx":  "del?x",
		"c1\u0085x": "c1?x",
		"naïve 名前":  "naïve 名前",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskKeyID(t *testing.T) {
	cases := map[string]string{
		"AKIAIOSFODNN7EXAMPLE": "AKIA****MPLE",
		"":                     "",
		"short":                "****",
		"123456789012":         "1234****9012",
		"12345678901":          "****",
	}
	for in, want := range cases {
		if got := MaskKeyID(in); got != want {
			t.Errorf("MaskKeyID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	if SevHigh.String() != "HIGH" || SevOK.String() != "OK" || SevLow.String() != "LOW" || SevMed.String() != "MED" {
		t.Error("bad Severity strings")
	}
	if !(SevHigh > SevMed && SevMed > SevLow && SevLow > SevOK) {
		t.Error("bad Severity order")
	}
}
