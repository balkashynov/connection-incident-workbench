package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestEvidenceOutputIsExclusiveAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := write(path, func(w io.Writer) error { _, err := io.WriteString(w, "original"); return err }); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", st.Mode().Perm())
	}
	if err := write(path, func(w io.Writer) error { _, err := io.WriteString(w, "overwritten"); return err }); err == nil {
		t.Fatal("replaced evidence")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := write(link, func(w io.Writer) error { _, err := io.WriteString(w, "followed symlink"); return err }); err == nil {
		t.Fatal("followed output symlink")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatal("original modified")
	}
	partial := filepath.Join(dir, "partial.json")
	if err := write(partial, func(w io.Writer) error { io.WriteString(w, "partial"); return errors.New("render failed") }); err == nil {
		t.Fatal("ignored rendering error")
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatal("left partial evidence")
	}
}
