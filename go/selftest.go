package main

// Show what the collectors can and cannot open, and prove the guards with
// probes rather than assertions in a comment.

import (
	"fmt"
	"os"
	"path/filepath"
)

func selftest() {
	// What an Android process can and cannot reach, first: on a phone this is
	// the whole question (android_linux.go).
	androidSelftest()
	root := codexSessionsDir()
	fmt.Println("sessions root :", root)
	st, err := os.Stat(root)
	fmt.Println("exists        :", err == nil && st.IsDir())

	if err == nil && st.IsDir() {
		cands, partial := codexCandidates(root)
		fmt.Printf("rollouts found: %d (scan stops on mtime, usually after 1)\n", len(cands))
		if partial {
			fmt.Println("  ⚠ part of the tree was unreadable — listing is incomplete")
		}
		r, err := os.OpenRoot(root)
		if err == nil {
			defer r.Close()
			for i, c := range cands {
				if i >= 3 {
					break
				}
				f, err := r.Open(c.rel)
				// The link count belongs next to `opened`, because a file
				// that opens perfectly and is then refused for having a
				// second name looks identical from here otherwise. 1 is the
				// only value this collector will read; anything else (0 = the
				// platform would not say) is why the card says nothing.
				fmt.Printf("  %s\n    opened=%v nlink=%d\n",
					c.rel, err == nil, linkCount(filepath.Join(root, c.rel)))
				if f != nil {
					f.Close()
				}
			}
			hardlinkProbe(r, root)
			symlinkProbe(r, root)
		}
	}

	fmt.Println("\nclaude:")
	auth, ok := readClaudeAuth()
	fmt.Println("  credential present:", ok)
	if ok {
		// Never the token. Length only — enough to see it was read, useless
		// to anyone reading the output over your shoulder.
		fmt.Printf("  token length      : %d (never printed, never logged, never pushed)\n", len(auth.token))
		fmt.Println("  plan / tier       :", auth.plan, "/", auth.tier)
	}
}

// A hard link is the case a path check cannot see: a genuine name inside the
// tree pointing at somebody else's inode. Links a file WE created and filled
// with nothing — never the real auth.json. An earlier version of the Python
// linked the credential file itself to demonstrate this, which was a genuinely
// bad idea: a kill between link and unlink leaves a second name for the
// credentials lying in the sessions tree, and once auth.json is later replaced
// atomically the orphan's link count falls back to 1 and the collector would
// happily read it. The guard counts links; it does not care whose inode.
func hardlinkProbe(r *os.Root, root string) {
	// A fixed name would truncate whatever the user already had there and
	// then delete it. CreateTemp fails rather than clobbering.
	tf, err := os.CreateTemp(root, ".probe-target-*")
	if err != nil {
		fmt.Println("  hardlink probe skipped:", err)
		return
	}
	target := tf.Name()
	tf.WriteString("{}\n")
	tf.Close()
	defer os.Remove(target)
	link := filepath.Join(root, fmt.Sprintf("rollout-probe-%d.jsonl", os.Getpid()))
	if err := os.Link(target, link); err != nil {
		fmt.Println("  hardlink probe skipped:", err)
		return
	}
	defer os.Remove(link)

	rec, _, _ := codexScanFile(r, filepath.Base(link))
	refused := rec == nil
	// Confirm the probe actually built the shape it claims to test. 0 means the
	// platform would not say, which is worth printing rather than hiding: it is
	// also the reading that makes the guard above refuse everything.
	fmt.Printf("  hardlink probe    : nlink=%d refused=%v\n", linkCount(link), refused)
}

// The case an O_NOFOLLOW on the final component misses: the last component is
// an ordinary file, reached through a directory that was swapped for a link
// elsewhere. Points at a throwaway temp dir, never anything sensitive — the
// guard refuses based on the link, not on where it leads.
func symlinkProbe(r *os.Root, root string) {
	outside, err := os.MkdirTemp("", "subnsub-helper-probe-")
	if err != nil {
		fmt.Println("  symlink probe skipped:", err)
		return
	}
	defer os.RemoveAll(outside)
	if err := os.WriteFile(filepath.Join(outside, "rollout-outside.jsonl"), []byte("{}\n"), 0o600); err != nil {
		fmt.Println("  symlink probe skipped:", err)
		return
	}
	link := filepath.Join(root, fmt.Sprintf("probe-dir-%d", os.Getpid()))
	if err := os.Symlink(outside, link); err != nil {
		fmt.Println("  symlink probe skipped:", err)
		return
	}
	defer os.Remove(link) // removes the LINK, never follows into it

	rec, _, _ := codexScanFile(r, filepath.Join(filepath.Base(link), "rollout-outside.jsonl"))
	fmt.Printf("  symlink probe     : parent symlink refused=%v\n", rec == nil)
}
