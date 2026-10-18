//go:build ignore

// Command hashgen prints an argon2id PHC hash for the perf harness.
//
// It lives inside the nested mdnsperf module on purpose: the harness is
// committed next to the load generators, but the file is compiled with the
// repository module (it imports mydns/internal/auth). The build tag keeps
// `go build ./...` inside e2e/perf from picking it up; run it explicitly:
//
//	go run ./e2e/perf/hashgen/main.go <password>
package main

import (
	"fmt"
	"os"

	"mydns/internal/auth"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./e2e/perf/hashgen/main.go <password>")
		os.Exit(2)
	}
	h, err := auth.HashPassword(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "hashgen:", err)
		os.Exit(1)
	}
	fmt.Println(h)
}
