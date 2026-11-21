package main

import (
	"os"

	"github.com/VSN2015/agentctl/internal/cli"
)

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func main() {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	io := cli.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr,
		InIsTTY: isTTY(os.Stdin), OutIsTTY: isTTY(os.Stdout), ErrIsTTY: isTTY(os.Stderr),
		Getenv: os.Getenv, Home: home, Cwd: cwd}
	os.Exit(cli.Run(os.Args[1:], io))
}
