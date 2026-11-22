// Package docker finds Docker sockets and says whether the current user can connect to them.
//
// Candidates: DOCKER_HOST when set (the only one, as the Docker CLI does; only unix:// with an
// absolute path is probed), else /var/run/docker.sock, ~/.docker/run/docker.sock (Docker Desktop
// on macOS), ~/.colima/default/docker.sock and $XDG_RUNTIME_DIR/docker.sock (rootless Linux).
// Not covered: Docker CLI contexts (~/.docker/config.json), Rancher Desktop, Podman, and tcp://
// or ssh:// hosts. The probe is a plain connect that sends nothing and closes at once.
//
// Known limits: when DOCKER_HOST is set it is the only location checked, so a live default socket
// is not reported; and the probe is a connect(), which on a host using systemd socket activation
// can start a stopped Docker daemon.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

var schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)

type Scanner struct {
	systemSocket string // tests override this
}

func New() *Scanner { return &Scanner{systemSocket: "/var/run/docker.sock"} }

func (s *Scanner) Name() string     { return "docker" }
func (s *Scanner) Provider() string { return "Docker" }
func (s *Scanner) LocalOnly()       {}

func (s *Scanner) Resolve(context.Context, model.Credential) (*model.Resolution, error) {
	return nil, &scan.SkipError{Reason: "nothing to resolve online"}
}

// classify turns a connect error into the credential kind and note. Only a clearly unreachable
// socket is downgraded; any other failure keeps it flagged, because a live socket must not be hidden.
func classify(err error) (kind, note string) {
	switch {
	case err == nil:
		return "socket", ""
	case errors.Is(err, fs.ErrPermission):
		return "socket-unreachable", "permission denied"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "socket-unreachable", "nothing is listening"
	case errors.Is(err, fs.ErrNotExist):
		return "socket-unreachable", "socket no longer exists"
	}
	return "socket", "could not confirm the socket accepts connections"
}

func (s *Scanner) Discover(env scan.Env) ([]model.Credential, error) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	var paths []string
	fromEnv := false
	if h := getenv("DOCKER_HOST"); h != "" {
		path, ok := strings.CutPrefix(h, "unix://")
		if !ok {
			scheme, _, found := strings.Cut(h, "://")
			if !found || !schemeRe.MatchString(scheme) {
				scheme = "non-unix"
			}
			return nil, fmt.Errorf("DOCKER_HOST is a %s endpoint, not a unix socket; not checked, and default socket locations were not checked either", model.Sanitize(scheme))
		}
		paths, fromEnv = []string{path}, true
	} else {
		paths = []string{s.systemSocket}
		if env.Home != "" {
			paths = append(paths, filepath.Join(env.Home, ".docker", "run", "docker.sock"),
				filepath.Join(env.Home, ".colima", "default", "docker.sock"))
		}
		if x := getenv("XDG_RUNTIME_DIR"); x != "" {
			paths = append(paths, filepath.Join(x, "docker.sock"))
		}
	}

	homes := []string{}
	if env.Home != "" {
		homes = append(homes, env.Home)
		if h, err := filepath.EvalSymlinks(env.Home); err == nil && h != env.Home {
			homes = append(homes, h)
		}
	}
	seen := map[string]bool{}
	var creds []model.Credential
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			continue
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode()&fs.ModeSocket == 0 {
			continue
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		label := real
		for _, h := range homes {
			if rest, ok := strings.CutPrefix(real, h+string(filepath.Separator)); ok {
				label = "~/" + rest
				break
			}
		}
		c := model.Credential{Tool: "docker", ID: real, Label: model.Sanitize(label), Kind: "socket", Source: "file"}
		if fromEnv {
			c.Source, c.EnvVars = "env", []string{"DOCKER_HOST"}
		}
		conn, err := net.DialTimeout("unix", real, time.Second)
		if err == nil {
			conn.Close()
		}
		var note string
		c.Kind, note = classify(err)
		if note != "" {
			c.Notes = []string{note}
		}
		creds = append(creds, c)
	}
	sort.Slice(creds, func(i, j int) bool { return creds[i].ID < creds[j].ID })
	return creds, nil
}
