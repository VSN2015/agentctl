package docker

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VSN2015/agentctl/internal/model"
	"github.com/VSN2015/agentctl/internal/scan"
)

// sockDir returns a short temp dir: macOS limits unix socket paths to about 104 bytes.
func sockDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "ac")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func listen(t *testing.T, path string) (*net.UnixListener, *atomic.Int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ul := l.(*net.UnixListener)
	t.Cleanup(func() { ul.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 64)
				for {
					k, err := c.Read(buf)
					n.Add(int64(k))
					if err != nil {
						break
					}
				}
				c.Close()
			}()
		}
	}()
	return ul, &n
}

func env(home string, vars map[string]string) scan.Env {
	return scan.Env{Home: home, Getenv: func(k string) string { return vars[k] }}
}

func newScanner(dir string) *Scanner {
	s := New()
	s.systemSocket = filepath.Join(dir, "no-such.sock")
	return s
}

func TestDiscoverDockerHost(t *testing.T) {
	d := sockDir(t)
	sock := filepath.Join(d, "d.sock")
	listen(t, sock)
	real, _ := filepath.EvalSymlinks(sock)
	creds, err := newScanner(d).Discover(env(d, map[string]string{"DOCKER_HOST": "unix://" + sock}))
	if err != nil || len(creds) != 1 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
	c := creds[0]
	if c.ID != real || c.Kind != "socket" || c.Source != "env" || len(c.EnvVars) != 1 || c.EnvVars[0] != "DOCKER_HOST" || c.Tool != "docker" {
		t.Fatalf("got %+v", c)
	}
}

func TestDiscoverDockerHostOverridesDefaults(t *testing.T) {
	d := sockDir(t)
	listen(t, filepath.Join(d, ".docker", "run", "docker.sock"))
	creds, err := newScanner(d).Discover(env(d, map[string]string{"DOCKER_HOST": "unix://" + filepath.Join(d, "missing.sock")}))
	if err != nil || len(creds) != 0 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
}

func TestDiscoverDefaultSockets(t *testing.T) {
	d := sockDir(t)
	listen(t, filepath.Join(d, ".docker", "run", "docker.sock"))
	listen(t, filepath.Join(d, ".colima", "default", "docker.sock"))
	creds, err := newScanner(d).Discover(env(d, nil))
	if err != nil || len(creds) != 2 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
	labels := map[string]bool{}
	for _, c := range creds {
		labels[c.Label] = true
		if c.Source != "file" || c.Kind != "socket" || len(c.Files) != 0 {
			t.Fatalf("got %+v", c)
		}
	}
	if !labels["~/.docker/run/docker.sock"] || !labels["~/.colima/default/docker.sock"] {
		t.Fatalf("labels %v", labels)
	}
	x := sockDir(t)
	listen(t, filepath.Join(x, "docker.sock"))
	creds, err = newScanner(d).Discover(env(d, map[string]string{"XDG_RUNTIME_DIR": x}))
	if err != nil || len(creds) != 3 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
}

func TestDiscoverSymlinkListedOnce(t *testing.T) {
	d := sockDir(t)
	sock := filepath.Join(d, ".docker", "run", "docker.sock")
	listen(t, sock)
	s := New()
	s.systemSocket = filepath.Join(d, "link.sock")
	if err := os.Symlink(sock, s.systemSocket); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(sock)
	creds, err := s.Discover(env(d, nil))
	if err != nil || len(creds) != 1 || creds[0].ID != real {
		t.Fatalf("creds=%v err=%v want %s", creds, err, real)
	}
}

func TestDiscoverStaleSocket(t *testing.T) {
	d := sockDir(t)
	sock := filepath.Join(d, "d.sock")
	l, _ := listen(t, sock)
	l.SetUnlinkOnClose(false)
	l.Close()
	creds, err := newScanner(d).Discover(env(d, map[string]string{"DOCKER_HOST": "unix://" + sock}))
	if err != nil || len(creds) != 1 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
	if creds[0].Kind != "socket-unreachable" || !strings.Contains(strings.Join(creds[0].Notes, " "), "nothing is listening") {
		t.Fatalf("got %+v", creds[0])
	}
}

func TestDiscoverPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores socket permissions")
	}
	d := sockDir(t)
	sock := filepath.Join(d, "d.sock")
	listen(t, sock)
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	creds, err := newScanner(d).Discover(env(d, map[string]string{"DOCKER_HOST": "unix://" + sock}))
	if err != nil || len(creds) != 1 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
	if creds[0].Kind != "socket-unreachable" || !strings.Contains(strings.Join(creds[0].Notes, " "), "permission denied") {
		t.Fatalf("got %+v", creds[0])
	}
}

func TestDiscoverIgnoresNonSockets(t *testing.T) {
	d := sockDir(t)
	s := New()
	s.systemSocket = filepath.Join(d, "plain")
	if err := os.WriteFile(s.systemSocket, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, vars := range []map[string]string{nil, {"DOCKER_HOST": "unix://rel.sock"}} {
		creds, err := s.Discover(env(d, vars))
		if err != nil || len(creds) != 0 {
			t.Fatalf("vars=%v creds=%v err=%v", vars, creds, err)
		}
	}
	creds, err := newScanner(d).Discover(env("", nil))
	if err != nil || len(creds) != 0 {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
}

func TestDiscoverRemoteDockerHost(t *testing.T) {
	d := sockDir(t)
	creds, err := newScanner(d).Discover(env(d, map[string]string{"DOCKER_HOST": "tcp://user:CANARY-PW@10.0.0.1:2375"}))
	if len(creds) != 0 || err == nil {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
	if !strings.Contains(err.Error(), "tcp") || strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("err=%v", err)
	}
}

func TestDiscoverSendsNothing(t *testing.T) {
	d := sockDir(t)
	sock := filepath.Join(d, "d.sock")
	_, n := listen(t, sock)
	creds, err := newScanner(d).Discover(env(d, map[string]string{"DOCKER_HOST": "unix://" + sock}))
	if err != nil || len(creds) != 1 || creds[0].Kind != "socket" {
		t.Fatalf("creds=%v err=%v", creds, err)
	}
	time.Sleep(100 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatalf("scanner sent %d bytes", n.Load())
	}
}

func TestResolveSkips(t *testing.T) {
	_, err := New().Resolve(nil, model.Credential{})
	var skip *scan.SkipError
	if !errors.As(err, &skip) {
		t.Fatalf("err=%v", err)
	}
}

func TestDiscoverDockerHostOddValueNeverEchoed(t *testing.T) {
	v := "admin:CANARY-PW@host:2375/x?u=http://y"
	creds, err := New().Discover(scan.Env{Getenv: func(k string) string {
		if k == "DOCKER_HOST" {
			return v
		}
		return ""
	}})
	if len(creds) != 0 || err == nil {
		t.Fatalf("creds %v err %v", creds, err)
	}
	for _, bad := range []string{"CANARY", "admin", "host"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("error echoes %q: %v", bad, err)
		}
	}
	if !strings.Contains(err.Error(), "non-unix") {
		t.Errorf("error %v lacks non-unix", err)
	}
}
