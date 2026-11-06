package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const unregisterTimeout = 10 * time.Second

// unregisterMachine makes the one explicit, idempotent removal request. It
// deliberately reads the existing id rather than agentID(): uninstall must
// never create a new machine merely to remove it.
func unregisterMachine(relay string, client *http.Client) error {
	dir := configDir()
	if dir == "" {
		return errors.New("installation configuration is unavailable")
	}
	idBytes, err := os.ReadFile(filepath.Join(dir, "agent-id"))
	if err != nil {
		return errors.New("installed machine id is unavailable")
	}
	id := cleanID(string(idBytes))
	if id == "" {
		return errors.New("installed machine id is invalid")
	}

	bootstrap := installedEnv()[tokenEnv]
	token := resolveStartToken(relay, bootstrap)
	if token == "" {
		return errors.New("installed machine credential is unavailable")
	}
	body, err := json.Marshal(struct {
		Agent string `json:"agent"`
	}{Agent: id})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, trimRelay(relay)+"/uninstall", bytes.NewReader(body))
	if err != nil {
		return errors.New("configured relay URL is invalid")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "subnsub-helper")
	if client == nil {
		client = &http.Client{
			Timeout:   unregisterTimeout,
			Transport: relayTransport(),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("relay rejected request: %d", resp.StatusCode)
	}
	return nil
}

func trimRelay(relay string) string {
	for len(relay) > 0 && relay[len(relay)-1] == '/' {
		relay = relay[:len(relay)-1]
	}
	return relay
}
