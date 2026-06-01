// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"bufio"
	"bytes"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// goSymtabMagic identifies the side-car file produced next to a Go EXE
// that is intended to act as a host for plugins on Windows.
//
// The file is a UTF-8 text format with one record per line so it is
// trivial to inspect. It is read back when linking a plugin DLL with
// -pluginhost=<host>.exe to figure out which symbols the plugin must
// import (rather than redefine).
//
// Format:
//
//	GOSYMTAB v1
//	HOST <abs path of host exe>
//	PKG  <pkg-path> <16-hex-byte fingerprint>
//	...
//	SYM  <symbol-name> <type> <size>
//	...
//
// Where <type> is one of T (text/function), D (data), R (rodata), B (bss).
const goSymtabMagic = "GOSYMTAB v1"

// gosymtabEntry is a single record in the host's exported symbol table.
type gosymtabEntry struct {
	Name string
	Type byte // 'T', 'D', 'R', 'B'
	Size int64
}

// gosymtabPkg records the link-time fingerprint of a package linked into
// the host. A plugin is allowed to reuse that package's symbols only if
// its own fingerprint matches.
type gosymtabPkg struct {
	Path        string
	Fingerprint string // 16 hex bytes
}

// gosymtab is the in-memory representation of a parsed .gosymtab.
type gosymtab struct {
	HostPath string
	Pkgs     []gosymtabPkg
	Syms     []gosymtabEntry
}

// writeGoSymtab is invoked at the end of the host link (when ctxt.canUsePlugins
// is true and we are not ourselves a plugin) to dump the side-car file.
//
// path is typically <flagOutfile>.gosymtab.
func writeGoSymtab(ctxt *Link, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	if err := writeGoSymtabTo(ctxt, w); err != nil {
		return err
	}
	return w.Flush()
}

// goSymtabBytes returns the .gosymt section payload for the current
// host link. The caller is responsible for emitting it as a PE section.
func goSymtabBytes(ctxt *Link) []byte {
	var buf bytes.Buffer
	// writeGoSymtabTo never fails when writing to a bytes.Buffer.
	_ = writeGoSymtabTo(ctxt, &buf)
	return buf.Bytes()
}

// writeGoSymtabTo serializes the host's exported symbol table to w.
func writeGoSymtabTo(ctxt *Link, w io.Writer) error {
	bw := bufio.NewWriter(w)

	fmt.Fprintln(bw, goSymtabMagic)
	fmt.Fprintf(bw, "HOST %s\n", *flagOutfile)

	// Package fingerprints. ctxt.Library carries the link-time fingerprint
	// already; the plugin will compare the entries it shares with the host.
	for _, lib := range ctxt.Library {
		fmt.Fprintf(bw, "PKG  %s %x\n", lib.Pkg, lib.Fingerprint[:])
	}

	// Reachable defined symbols of "real" types. We deliberately skip
	// link-internal helpers (go:link.*, local.*) and DWARF/debug data,
	// because the plugin must never re-bind those.
	ldr := ctxt.loader
	type rec struct {
		name string
		t    byte
		size int64
	}
	var recs []rec
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) {
			continue
		}
		name := ldr.SymName(s)
		if name == "" || strings.HasPrefix(name, "go:link.") || strings.HasPrefix(name, "local.") {
			continue
		}
		t := ldr.SymType(s)
		var k byte
		switch {
		case t.IsText():
			k = 'T'
		case t == sym.SRODATA, t == sym.STYPE, t == sym.SSTRING, t == sym.SGOSTRING, t == sym.SGOFUNC, t == sym.SFUNCTAB, t == sym.STYPELINK, t == sym.SITABLINK:
			k = 'R'
		case t == sym.SDATA, t == sym.SNOPTRDATA, t == sym.SINITARR:
			k = 'D'
		case t == sym.SBSS, t == sym.SNOPTRBSS:
			k = 'B'
		default:
			continue
		}
		recs = append(recs, rec{name, k, ldr.SymSize(s)})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].name < recs[j].name })
	for _, r := range recs {
		// Put the (possibly space-bearing) name LAST so the reader can
		// recover it as the rest of the line.
		fmt.Fprintf(bw, "SYM %c %d %s\n", r.t, r.size, r.name)
	}
	return bw.Flush()
}

// readGoSymtab parses a side-car file written by writeGoSymtab. It is
// invoked when linking a plugin DLL with -pluginhost=<host.exe>.
func readGoSymtab(path string) (*gosymtab, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseGoSymtab(f, path)
}

// readGoSymtabSection reads the embedded .gosymt section out of a Go host
// EXE. Returns os.ErrNotExist if the EXE was not built with plugin
// support (i.e. has no such section).
func readGoSymtabSection(path string) (*gosymtab, error) {
	pf, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open host PE: %v", err)
	}
	defer pf.Close()
	sect := pf.Section(".gosymt")
	if sect == nil {
		return nil, os.ErrNotExist
	}
	data, err := sect.Data()
	if err != nil {
		return nil, fmt.Errorf("read .gosymt: %v", err)
	}
	// virtualSize < sizeOfRawData (zero-padded by PE alignment); trim trailing NULs.
	if sect.VirtualSize < uint32(len(data)) {
		data = data[:sect.VirtualSize]
	}
	return parseGoSymtab(bytes.NewReader(data), path+":.gosymt")
}

// parseGoSymtab is the shared parser for both readGoSymtab (sidecar
// file) and readGoSymtabSection (embedded PE section).
func parseGoSymtab(r io.Reader, path string) (*gosymtab, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	if !sc.Scan() {
		return nil, fmt.Errorf("%s: empty", path)
	}
	if line := sc.Text(); line != goSymtabMagic {
		return nil, fmt.Errorf("%s: bad magic %q (expected %q)", path, line, goSymtabMagic)
	}
	out := &gosymtab{}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "HOST "):
			out.HostPath = strings.TrimPrefix(line, "HOST ")
		case strings.HasPrefix(line, "PKG  "), strings.HasPrefix(line, "PKG "):
			parts := strings.Fields(line)
			if len(parts) != 3 {
				return nil, fmt.Errorf("%s: bad PKG record %q", path, line)
			}
			out.Pkgs = append(out.Pkgs, gosymtabPkg{Path: parts[1], Fingerprint: parts[2]})
		case strings.HasPrefix(line, "SYM "):
			// SYM <type> <size> <name>  (name may contain spaces)
			rest := line[4:]
			parts := strings.SplitN(rest, " ", 3)
			if len(parts) != 3 || len(parts[0]) != 1 {
				return nil, fmt.Errorf("%s: bad SYM record %q", path, line)
			}
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s: bad size in %q: %v", path, line, err)
			}
			out.Syms = append(out.Syms, gosymtabEntry{
				Name: parts[2],
				Type: parts[0][0],
				Size: size,
			})
		}
	}
	return out, sc.Err()
}

// indexSymtab returns a map from symbol name to entry, for fast lookup
// while resolving the plugin's external references.
func (g *gosymtab) indexSymtab() map[string]gosymtabEntry {
	m := make(map[string]gosymtabEntry, len(g.Syms))
	for _, s := range g.Syms {
		m[s.Name] = s
	}
	return m
}

// indexPkgs returns the package-fingerprint map.
func (g *gosymtab) indexPkgs() map[string]string {
	m := make(map[string]string, len(g.Pkgs))
	for _, p := range g.Pkgs {
		m[p.Path] = p.Fingerprint
	}
	return m
}
