package run

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/VSN2015/agentctl/internal/model"
)

func TestFakeToolAndAgentFlowThroughPipelineAndRenderers(t *testing.T) {
	run := func(o Options) (int, string) {
		r := newRig()
		code := Execute(context.Background(), o, r.deps())
		return code, r.out.String()
	}
	code, text := run(doctor())
	if code != 0 || !strings.Contains(text, "Fakery") || !strings.Contains(text, "label c1") || !strings.Contains(text, "fake risk headline") {
		t.Errorf("doctor text exit %d:\n%s", code, text)
	}
	code, js := run(doctor(func(o *Options) { o.JSON = true }))
	var doc struct {
		Findings    []struct{ ID, Agent, Tool string }
		Credentials []struct {
			Agents []struct{ Agent string }
		}
	}
	if err := json.Unmarshal([]byte(js), &doc); err != nil || code != 0 {
		t.Fatalf("doctor json exit %d err %v:\n%s", code, err, js)
	}
	if f := doc.Findings[0]; f.Agent != "fake-agent" || f.Tool != "fake" || f.ID != "fake-agent:fake:c1" || doc.Credentials[0].Agents[0].Agent != "fake-agent" {
		t.Errorf("doc = %+v", doc)
	}
	_, text = run(inventory())
	if !strings.Contains(text, "label c1") || !strings.Contains(text, "fake-agent") {
		t.Errorf("inventory text:\n%s", text)
	}
	o := inventory()
	o.JSON = true
	_, js = run(o)
	if !strings.Contains(js, `"fake-agent"`) || !strings.Contains(js, "label c1") {
		t.Errorf("inventory json:\n%s", js)
	}
	_ = bytes.Buffer{}
	_ = model.SevOK
}

func TestSourcesHaveNoPerToolLiterals(t *testing.T) {
	banned := map[string]bool{"aws": true, "gh": true, "claude-code": true}
	for _, pat := range []string{"*.go", "../render/*.go"} {
		files, _ := filepath.Glob(pat)
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
					if s, err := strconv.Unquote(l.Value); err == nil && banned[s] {
						t.Errorf("%s: literal %s", f, l.Value)
					}
				}
				return true
			})
		}
	}
}
