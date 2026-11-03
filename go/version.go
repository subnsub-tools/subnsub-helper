package main

// What this build calls itself.
//
// ★ BUMP THIS IN THE SAME COMMIT THAT PUBLISHES NEW BINARIES. A release whose
// version did not move is worse than no version at all: every machine claims
// to be current, the dashboard says nothing needs updating, and the one
// mechanism meant to surface stale helpers reports the opposite of the truth.
//
// A plain constant rather than an -ldflags stamp, because the two source trees
// this file lives in have to compile to byte-identical binaries — the public
// mirror's whole reproducibility claim rests on that — and a value injected at
// build time is one more thing that has to match exactly in two places instead
// of being the same characters in the same file.
//
// YYYY.MM.DD.N, compared component by component AS NUMBERS, never as strings:
// "2026.7.9" sorts after "2026.7.30" lexically and before it in every sense
// that matters. N counts releases within a day and starts at 1, because two
// releases on one date is an ordinary Tuesday and a version that cannot
// express it silently reports the earlier build as current.
const helperVersion = "2026.11.04.1"
