package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"connection-workbench/internal/workbench"
)

func read(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return workbench.Decode(f, out)
}

// Exclusive creation avoids silently replacing evidence or following an output symlink.
func write(path string, fn func(io.Writer) error) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = fn(f); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: connection-workbench collect|analyze|report|export [options]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	out := fs.String("out", "", "new output file (required)")
	switch args[0] {
	case "collect":
		role := fs.String("role", "source", "source or router")
		incident := fs.String("incident", "", "shared incident identifier")
		target := fs.String("target", "", "name:port")
		address := fs.String("address", "", "explicit destination IP")
		router := fs.String("router", "", "explicit selected router Tailscale IP")
		socket := fs.String("socket", "", "LocalAPI Unix socket override")
		timeout := fs.Duration("timeout", 2*time.Second, "deadline per probe, at most 30s")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *out == "" {
			return errors.New("--out required; unexpected positional arguments")
		}
		host, port, err := net.SplitHostPort(*target)
		if err != nil {
			return err
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return errors.New("invalid port")
		}
		b, err := workbench.Collect(context.Background(), workbench.CollectOptions{Role: *role, IncidentID: *incident, Host: host, Address: *address, Port: uint16(n), Router: *router, Socket: *socket, Timeout: *timeout})
		if err != nil {
			return err
		}
		return write(*out, func(w io.Writer) error { e := json.NewEncoder(w); e.SetIndent("", "  "); return e.Encode(b) })
	case "analyze":
		source := fs.String("source", "", "source bundle")
		router := fs.String("router", "", "optional router bundle")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *out == "" {
			return errors.New("--out required; unexpected positional arguments")
		}
		var s workbench.Bundle
		if err := read(*source, &s); err != nil {
			return err
		}
		bundles := []workbench.Bundle{s}
		if *router != "" {
			var r workbench.Bundle
			if err := read(*router, &r); err != nil {
				return err
			}
			bundles = append(bundles, r)
		}
		in, err := workbench.Analyze(bundles)
		if err != nil {
			return err
		}
		return write(*out, func(w io.Writer) error { e := json.NewEncoder(w); e.SetIndent("", "  "); return e.Encode(in) })
	case "report", "export":
		input := fs.String("input", "", "incident JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *out == "" {
			return errors.New("--out required; unexpected positional arguments")
		}
		var in workbench.Incident
		if err := read(*input, &in); err != nil {
			return err
		}
		if in.SchemaVersion != 1 {
			return errors.New("unsupported incident schema")
		}
		var err error
		in, err = workbench.Analyze(in.Bundles)
		if err != nil {
			return err
		}
		if args[0] == "report" {
			return write(*out, func(w io.Writer) error { return workbench.Report(w, in) })
		}
		in, err = workbench.Redact(in)
		if err != nil {
			return err
		}
		return write(*out, func(w io.Writer) error { e := json.NewEncoder(w); e.SetIndent("", "  "); return e.Encode(in) })
	default:
		return errors.New("unknown command")
	}
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
