//go:build unix

// GitHub first, this site when GitHub cannot be reached (update.go
// updateFromSrcs): which answers move the update on to the next source and
// which never do.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A release as GitHub lays it out: latest/download/VERSION, and the files
// under download/v<version>/.
type fakeGitHub struct {
	version string
	binary  []byte
	sums    string
	hits    map[string]int
	srv     *httptest.Server
	status  int // answered to everything when non-zero
}

func newGitHub(t *testing.T, version, script string) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{version: version, binary: []byte(script), hits: map[string]int{}}
	sum := sha256.Sum256(g.binary)
	asset := "subnsub-helper-" + runtime.GOOS + "-" + runtime.GOARCH
	g.sums = hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		g.hits[req.URL.Path]++
		if g.status != 0 {
			w.WriteHeader(g.status)
			return
		}
		switch req.URL.Path {
		case "/latest/download/VERSION":
			w.Write([]byte(g.version + "\n"))
		case "/download/v" + g.version + "/SHA256SUMS":
			w.Write([]byte(g.sums))
		case "/download/v" + g.version + "/" + asset:
			w.Write(g.binary)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(g.srv.Close)
	return g
}

// An address nothing listens on: GitHub out of reach.
func goneURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := "http://" + l.Addr().String()
	l.Close()
	return u
}

// An install directory under a home of the test's own, so the
// update-github-down file lands there.
func githubHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", helperName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	githubDownSince.Lock()
	githubDownSince.t = time.Time{}
	githubDownSince.Unlock()
	t.Cleanup(func() {
		githubDownSince.Lock()
		githubDownSince.t = time.Time{}
		githubDownSince.Unlock()
	})
	return dir
}

func siteHits(r *fakeRelease) int {
	n := 0
	for _, v := range r.hits {
		n += v
	}
	return n
}

func TestUpdateTakesGitHubsRelease(t *testing.T) {
	githubHome(t)
	self := installed(t)
	gh := newGitHub(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(gh.srv.URL), siteSrc(site.srv.URL)}, func() bool { return true })
	if !swap || res.Code != 0 {
		t.Fatalf("not installed from GitHub: code=%d\n%s", res.Code, res.Out)
	}
	if siteHits(site) != 0 {
		t.Fatalf("the site was asked though GitHub answered: %v", site.hits)
	}
	if !strings.Contains(res.Out, "published 2999.12.31.9 on GitHub") {
		t.Fatalf("the report does not say where from:\n%s", res.Out)
	}
}

func TestUpdateAsksTheSiteWhenGitHubIsOutOfReach(t *testing.T) {
	dir := githubHome(t)
	self := installed(t)
	site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(goneURL(t)), siteSrc(site.srv.URL)}, func() bool { return true })
	if !swap || res.Code != 0 {
		t.Fatalf("a press should have gone on to the site: code=%d\n%s", res.Code, res.Out)
	}
	if !strings.Contains(res.Out, "asking 127.0.0.1") {
		t.Fatalf("the report does not say it asked the site:\n%s", res.Out)
	}
	if _, err := os.Stat(filepath.Join(dir, updateGitHubDownFile)); err != nil {
		t.Fatalf("since when GitHub is out of reach was not kept: %v", err)
	}

	// And GitHub answering again clears it.
	self = installed(t)
	gh := newGitHub(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	if _, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(gh.srv.URL), siteSrc(site.srv.URL)}, func() bool { return true }); !swap {
		t.Fatal("not installed from GitHub")
	}
	if _, err := os.Stat(filepath.Join(dir, updateGitHubDownFile)); !os.IsNotExist(err) {
		t.Fatalf("still marked out of reach after GitHub answered: %v", err)
	}
}

// The hourly look waits out the grace before it asks the site, counted
// from the first time GitHub could not be reached, across restarts.
func TestUpdateHourlyLookWaitsOutTheGrace(t *testing.T) {
	dir := githubHome(t)
	self := installed(t)
	site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	srcs := []updateSrc{githubSrc(goneURL(t)), siteSrc(site.srv.URL)}

	res, swap := updateFromSrcs("auto", self, srcs, githubDownLong)
	if swap || siteHits(site) != 0 {
		t.Fatalf("asked the site at the first miss: swap=%v hits=%v\n%s", swap, site.hits, res.Out)
	}
	// What autoUpdateLoop reads as "unreachable".
	if !strings.Contains(res.Out, "could not read the published version") || !strings.Contains(res.Out, "GitHub could not be reached") {
		t.Fatalf("the report does not say GitHub was out of reach:\n%s", res.Out)
	}

	// Seven hours ago, as a restarted helper finds it on disk.
	githubDownSince.Lock()
	githubDownSince.t = time.Time{}
	githubDownSince.Unlock()
	then := strconv.FormatInt(time.Now().Add(-7*time.Hour).Unix(), 10) + "\n"
	if err := os.WriteFile(filepath.Join(dir, updateGitHubDownFile), []byte(then), 0o600); err != nil {
		t.Fatal(err)
	}
	res, swap = updateFromSrcs("auto", self, srcs, githubDownLong)
	if !swap {
		t.Fatalf("still waiting after the grace:\n%s", res.Out)
	}
}

// An answer from GitHub is never a reason to ask the site: a version it
// does not have yet means wait, and a checksum that does not match is the
// thing the whole arrangement is for.
func TestUpdateNeverAsksTheSiteAfterAnAnswer(t *testing.T) {
	githubHome(t)
	always := func() bool { return true }

	t.Run("not found", func(t *testing.T) {
		self := installed(t)
		gh := newGitHub(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		gh.status = 404
		site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(gh.srv.URL), siteSrc(site.srv.URL)}, always)
		if swap || siteHits(site) != 0 {
			t.Fatalf("a 404 sent it to the site: swap=%v hits=%v\n%s", swap, site.hits, res.Out)
		}
	})
	t.Run("older on GitHub", func(t *testing.T) {
		self := installed(t)
		gh := newGitHub(t, "0001.01.01.1", versionScript("0001.01.01.1"))
		site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(gh.srv.URL), siteSrc(site.srv.URL)}, always)
		if swap || siteHits(site) != 0 || res.Error != "update-none" {
			t.Fatalf("a release not yet on GitHub sent it to the site: swap=%v err=%q hits=%v\n%s", swap, res.Error, site.hits, res.Out)
		}
	})
	t.Run("checksum mismatch", func(t *testing.T) {
		self := installed(t)
		gh := newGitHub(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		gh.sums = strings.Repeat("0", 64) + "  subnsub-helper-" + runtime.GOOS + "-" + runtime.GOARCH + "\n"
		site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(gh.srv.URL), siteSrc(site.srv.URL)}, always)
		if swap || siteHits(site) != 0 || !strings.Contains(res.Out, "checksum mismatch") {
			t.Fatalf("a mismatch sent it to the site: swap=%v hits=%v\n%s", swap, site.hits, res.Out)
		}
	})
	t.Run("server error", func(t *testing.T) {
		// GitHub's own trouble is no answer about the release: on to the site.
		self := installed(t)
		gh := newGitHub(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		gh.status = 503
		site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
		if res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(gh.srv.URL), siteSrc(site.srv.URL)}, always); !swap {
			t.Fatalf("a 503 did not send it to the site:\n%s", res.Out)
		}
	})
}

// GitHub's redirect to its download host is followed; one anywhere else is
// not, and the site never redirects at all.
func TestUpdateFollowsGitHubsRedirectOnly(t *testing.T) {
	if updateGitHubHostOK(&url.URL{Scheme: "https", Host: "evil.example"}) ||
		updateGitHubHostOK(&url.URL{Scheme: "http", Host: "github.com"}) ||
		!updateGitHubHostOK(&url.URL{Scheme: "https", Host: "release-assets.githubusercontent.com"}) ||
		!updateGitHubHostOK(&url.URL{Scheme: "https", Host: "github.com"}) {
		t.Fatal("the redirect host check is wrong")
	}

	githubHome(t)
	store := newGitHub(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, store.srv.URL+req.URL.Path, http.StatusFound)
	}))
	t.Cleanup(front.Close)
	storeHost := strings.TrimPrefix(store.srv.URL, "http://")

	old := updateGitHubHostOK
	t.Cleanup(func() { updateGitHubHostOK = old })
	updateGitHubHostOK = func(u *url.URL) bool { return u.Host == storeHost }
	self := installed(t)
	if res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(front.URL)}, nil); !swap {
		t.Fatalf("GitHub's redirect was not followed:\n%s", res.Out)
	}

	// Refused, and an answer: not a reason to ask the site.
	updateGitHubHostOK = func(*url.URL) bool { return false }
	self = installed(t)
	site := newRelease(t, "2999.12.31.9", versionScript("2999.12.31.9"))
	if res, swap := updateFromSrcs("cmd", self, []updateSrc{githubSrc(front.URL), siteSrc(site.srv.URL)}, func() bool { return true }); swap || siteHits(site) != 0 {
		t.Fatalf("a refused redirect: swap=%v site hits=%v\n%s", swap, site.hits, res.Out)
	}
	if siteSrc(front.URL).github {
		t.Fatal("the site's source follows redirects")
	}
}
