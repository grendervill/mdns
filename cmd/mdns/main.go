// Command mdns is the entrypoint of the mdns DNS server.
package main

import (
	"fmt"
	"os"

	"mydns/internal/version"
)

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "version":
		fmt.Printf("mdns %s\n", version.String())
		os.Exit(0)
	case "serve":
		fmt.Fprintln(os.Stderr, "mdns serve: not implemented")
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mdns <command> [arguments]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  version    print the mdns version")
	fmt.Fprintln(os.Stderr, "  serve      run the mdns DNS server")
}
