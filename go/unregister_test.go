package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func installUnregisterFixture(t *testing.T, relay string) (string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(tokenEnv, "")
	dir := filepath.Join(home, ".config", "subnsub-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, tok := "machine_123", legacyToken()
	if err := os.WriteFile(filepath.Join(dir, "agent-id"), []byte(id+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(tokenEnv+"="+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func TestUnregisterUsesInstalledIdentityAndCredential(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/uninstall" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+legacyToken() {
			t.Errorf("Authorization = %q", got)
		}
		var body struct {
			Agent string `json:"agent"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Agent != "machine_123" {
			t.Errorf("agent = %q", body.Agent)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	installUnregisterFixture(t, server.URL)
	if err := unregisterMachine(server.URL+"/", server.Client()); err != nil {
		t.Fatal(err)
	}
}

func TestUnregisterDoesNotCreateMissingIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := unregisterMachine("https://relay.example", &http.Client{}); err == nil {
		t.Fatal("expected missing installation error")
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "subnsub-helper", "agent-id")); !os.IsNotExist(err) {
		t.Fatalf("agent-id was created: %v", err)
	}
}

func TestUnregisterRejectsRedirect(t *testing.T) {
	destinationHit := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHit = true }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	installUnregisterFixture(t, source.URL)
	// Exercise the production client, not a test-supplied redirect policy.
	if err := unregisterMachine(source.URL, nil); err == nil {
		t.Fatal("redirect reported success")
	}
	if destinationHit {
		t.Fatal("redirect was followed")
	}
}

func TestUnregisterRejectsFailedNotification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	installUnregisterFixture(t, server.URL)
	if err := unregisterMachine(server.URL, nil); err == nil {
		t.Fatal("failed notification reported success")
	}
}
