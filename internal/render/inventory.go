package render

import (
	"strings"

	"github.com/VSN2015/agentctl/internal/model"
)

func accessText(a model.AgentState) string {
	switch a.Access {
	case model.AccessDenied:
		return "denied"
	case model.AccessAsks:
		return "asks first"
	}
	t := "allowed without asking"
	if a.FileBlocked {
		t += " (credential file blocked, tool still allowed)"
	}
	return t
}

func (p *printer) inventory(r Report) {
	var order []string
	groups := map[string][]model.Credential{}
	for _, c := range r.Credentials {
		if _, ok := groups[c.Provider]; !ok {
			order = append(order, c.Provider)
		}
		groups[c.Provider] = append(groups[c.Provider], c)
	}
	for i, prov := range order {
		if i > 0 {
			p.printf("\n")
		}
		p.printf("%s\n", s(prov))
		for _, c := range groups[prov] {
			p.credential(c)
		}
	}
}

func (p *printer) credential(c model.Credential) {
	p.printf("  %s %s %s\n", s(c.Label), p.dot(), s(c.Kind))
	id := c.Identity
	if c.Resolved != nil && c.Resolved.Identity != "" {
		id = c.Resolved.Identity
	}
	if id != "" {
		p.printf("    Identity: %s\n", s(id))
	}
	if c.KeyID != "" {
		p.printf("    Key: %s\n", s(c.KeyID))
	}
	if rs := c.Resolved; rs != nil {
		p.resolution(c, rs)
	}
	if len(c.EnvVars) > 0 {
		names := make([]string, len(c.EnvVars))
		for i, v := range c.EnvVars {
			names[i] = s(v)
		}
		p.printf("    Environment variables: %s\n", strings.Join(names, ", "))
	}
	for _, a := range c.Access {
		p.printf("    %s: %s\n", s(a.Agent), accessText(a))
	}
}

func (p *printer) resolution(c model.Credential, rs *model.Resolution) {
	why := ""
	if rs.AdminWhy != "" {
		why = " (" + s(rs.AdminWhy) + ")"
	}
	switch {
	case rs.AdminChecked && rs.Admin:
		p.printf("    Admin: yes%s\n", why)
	case rs.AdminChecked:
		p.printf("    Admin: no%s\n", why)
	case rs.AdminWhy != "": // never "not admin" for a credential whose policies were not read
		p.printf("    Admin: permissions could not be read%s\n", why)
	}
	switch {
	case rs.ScopesReadable && len(rs.Scopes) == 0:
		p.printf("    Scopes: none\n")
	case rs.ScopesReadable:
		sc := make([]string, len(rs.Scopes))
		for i, v := range rs.Scopes {
			sc[i] = s(v)
		}
		p.printf("    Scopes: %s\n", strings.Join(sc, ", "))
	case !rs.AdminChecked && rs.AdminWhy == "":
		p.printf("    Permissions: permissions cannot be read\n")
	}
	switch {
	case rs.KeyChecked && rs.KeyLastUsed != nil:
		svc := ""
		if rs.KeyLastUsedService != "" {
			svc = " (" + s(rs.KeyLastUsedService) + ")"
		}
		p.printf("    Key last used: %s%s\n", rs.KeyLastUsed.UTC().Format("2006-01-02"), svc)
	case rs.KeyChecked:
		p.printf("    Key last used: never used\n")
	case c.KeyID != "":
		p.printf("    Key last used: could not check\n")
	}
}
