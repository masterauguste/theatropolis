package tests

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Set THEATROPOLIS_TEST_CADDY to an installed Caddy binary to exercise the
// installer's actual template with automatic HTTPS redirects enabled. All
// listeners and storage are local; no certificate authority is contacted.
func TestInstallerACMERelayRouting(t *testing.T) {
	binary := os.Getenv("THEATROPOLIS_TEST_CADDY")
	if binary == "" {
		t.Skip("set THEATROPOLIS_TEST_CADDY to run the Caddy integration test")
	}
	installer, err := os.ReadFile("../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	_, template, found := strings.Cut(string(installer), "cat >\"$CADDY_RELAY_SNIPPET\" <<EOF\n")
	if !found {
		t.Fatal("installer relay template not found")
	}
	template, _, found = strings.Cut(template, "\nEOF")
	if !found {
		t.Fatal("installer relay template is unterminated")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-ACME", "forwarded")
		fmt.Fprint(w, "challenge-response")
	}))
	defer backend.Close()
	port := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	}
	httpPort, httpsPort := port(), port()
	const host = "control.example.com"
	template = strings.NewReplacer(
		"127.0.0.1:${ACME_HTTP01_RELAY_PORT}", strings.TrimPrefix(backend.URL, "http://"),
		"http://${RELAY_MASTER_HOST}", "http://"+host+":"+httpPort,
		"${LOCAL_MASTER_ADDRESS}", host+":"+httpsPort,
		":80 {", ":"+httpPort+" {",
	).Replace(template)
	config := fmt.Sprintf("{\n admin off\n persist_config off\n auto_https disable_certs\n default_bind 127.0.0.1\n http_port %s\n https_port %s\n}\nhttps://%s:%s {\n respond master\n}\n%s\n", httpPort, httpsPort, host, httpsPort, template)
	directory := t.TempDir()
	configPath := filepath.Join(directory, "Caddyfile")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(directory, "caddy.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(binary, "run", "--config", configPath, "--adapter", "caddyfile")
	command.Stdout, command.Stderr = log, log
	command.Env = append(os.Environ(), "XDG_DATA_HOME="+directory, "XDG_CONFIG_HOME="+directory)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		if t.Failed() {
			output, _ := os.ReadFile(log.Name())
			t.Log(string(output))
		}
	})
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	address := "http://127.0.0.1:" + httpPort
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(address)
		if err == nil {
			response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Caddy did not start: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	for _, name := range []string{host, "agent.example.com"} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
			for _, path := range []string{"/.well-known/acme-challenge/token", "/ordinary?query=1"} {
				t.Run(name+method+path, func(t *testing.T) {
					request, err := http.NewRequest(method, address+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					request.Host = name
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					_, _ = io.Copy(io.Discard, response.Body)
					challenge := method != http.MethodPost && strings.HasPrefix(path, "/.well-known/acme-challenge/")
					if forwarded := response.Header.Get("X-Test-ACME") == "forwarded"; forwarded != challenge {
						t.Fatalf("forwarded=%v want=%v status=%d location=%q", forwarded, challenge, response.StatusCode, response.Header.Get("Location"))
					}
					if challenge && response.StatusCode != http.StatusOK {
						t.Fatalf("challenge status=%d", response.StatusCode)
					}
					if !challenge && name == host {
						want := "https://" + host + ":" + httpsPort + path
						if response.StatusCode != http.StatusPermanentRedirect || response.Header.Get("Location") != want {
							t.Fatalf("ordinary request lost HTTPS redirect: status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
						}
					}
				})
			}
		}
	}
}
