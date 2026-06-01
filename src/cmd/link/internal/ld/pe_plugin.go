// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ld

import (
	"cmd/internal/objabi"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"fmt"
	"internal/buildcfg"
	"os"
	"path/filepath"
	"sort"
)

// This file contains the windows/amd64 implementation of plugin
// support, mirroring the dlopen-based path used on Linux/Darwin.
//
// The high-level flow is:
//
// 1. When linking a *host* EXE that imports the "plugin" package,
//    addPluginGoSymtab embeds a `.gosymt` PE section listing every
//    reachable symbol plus the package fingerprints. peAppendHostExports
//    widens the PE export table to cover every Go symbol the runtime
//    needs to share with plugins.
//
// 2. When linking a *plugin* DLL (BuildModePlugin) on windows/amd64,
//    loadPluginHostSidecar reads the gosymtab from the host's
//    `.gosymt` section (given by -pluginhost). peMarkPluginImports
//    rewrites every R_PEIMPORT relocation that targets a host-shared
//    symbol so it lands in the plugin's PE Import Address Table, which
//    the OS loader binds to the host EXE at LoadLibrary time.
//    Plugin-local copies of host-shared text symbols are replaced with
//    6-byte JMP-via-IAT thunks so direct calls trampoline to the host
//    implementation.

// addPluginGoSymtab emits the `.gosymt` PE section into the host EXE
// when the host imports the "plugin" package. The section payload is
// the same text format used by the legacy <exe>.gosymtab side-car file
// (magic "GOSYMTAB v1"), parsed by readGoSymtabSection at plugin link
// time.
func (f *peFile) addPluginGoSymtab(ctxt *Link) {
	if ctxt.HeadType != objabi.Hwindows {
		return
	}
	if ctxt.BuildMode == BuildModePlugin {
		return
	}
	if ctxt.LibraryByPkg["plugin"] == nil {
		return
	}
	data := goSymtabBytes(ctxt)
	if len(data) == 0 {
		return
	}
	sect := f.addSection(".gosymt", len(data), len(data))
	sect.characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	ctxt.Out.SeekSet(int64(sect.pointerToRawData))
	sect.checkOffset(ctxt.Out.Offset())
	ctxt.Out.Write(data)
	sect.pad(ctxt.Out, uint32(len(data)))
	if ctxt.Debugvlog > 0 {
		ctxt.Logf("plugin: embedded .gosymt section (%d bytes)\n", len(data))
	}
}

// loadPluginHostSidecar parses the host's symbol table and validates that
// the plugin's package fingerprints match the host's for every shared
// package. The table is read from the embedded `.gosymt` PE section of
// the host EXE; older hosts that wrote a `<exe>.gosymtab` side-car file
// are still accepted as a fallback.
func loadPluginHostSidecar(ctxt *Link) (*gosymtab, error) {
	if *flagPluginHost == "" {
		return nil, fmt.Errorf("buildmode=plugin on windows/amd64 requires -pluginhost=<path-to-host.exe>")
	}
	gs, err := readGoSymtabSection(*flagPluginHost)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading plugin host symtab from %s: %v", *flagPluginHost, err)
		}
		// Section missing: try the legacy side-car file.
		path := *flagPluginHost + ".gosymtab"
		gs, err = readGoSymtab(path)
		if err != nil {
			return nil, fmt.Errorf("reading plugin host symtab from %s: %v\n\thint: rebuild the host EXE with the patched toolchain so it embeds the .gosymt section", *flagPluginHost, err)
		}
	}

	// Validate that for every package the plugin shares with the host,
	// the link-time fingerprint matches. Fingerprint mismatches usually
	// indicate the host was built from different sources than the plugin.
	//
	// However, stdlib packages routinely show different fingerprints
	// because the host is built in default mode while the plugin uses
	// -buildmode=plugin (which flips -shared / -dynlink for stdlib).
	// We therefore downgrade mismatches to a Debugvlog-gated warning.
	hostPkgs := gs.indexPkgs()
	var mismatches []string
	for _, lib := range ctxt.Library {
		hostFP, ok := hostPkgs[lib.Pkg]
		if !ok {
			continue // plugin-only package; OK
		}
		ourFP := fmt.Sprintf("%x", lib.Fingerprint[:])
		if hostFP != ourFP {
			mismatches = append(mismatches, fmt.Sprintf("%s: host=%s plugin=%s", lib.Pkg, hostFP, ourFP))
		}
	}
	if len(mismatches) > 0 && ctxt.Debugvlog > 0 {
		ctxt.Logf("plugin: %d package fingerprint mismatch(es) vs %s (likely due to buildmode=plugin stdlib repackaging):\n", len(mismatches), *flagPluginHost)
		for _, m := range mismatches {
			ctxt.Logf("\t%s\n", m)
		}
	}
	return gs, nil
}

// peLinkPlugin is the windows/amd64 plugin-link entry point. Called
// from the PE writer when ctxt.BuildMode == BuildModePlugin, after
// dope() / initdynimport have already turned every host-shared symbol
// into a .windynamic IAT slot (see peMarkPluginImports below). At this
// stage there is nothing structural left to do — addimports() walks
// the SDYNIMPORT set and emits a real PE Import Directory pointing
// at the host EXE, and addPEBaseReloc() follows.
func peLinkPlugin(ctxt *Link) {
	if buildcfg.GOARCH != "amd64" {
		Exitf("buildmode=plugin on windows is only supported on amd64 (got %s)", buildcfg.GOARCH)
	}
	if ctxt.Debugvlog > 0 {
		ctxt.Logf("plugin: -buildmode=plugin output %s\n", *flagOutfile)
	}
}

// peMarkPluginImports is the early pass that runs before dope() /
// initdynimport(). It walks every reachable symbol's relocations
// looking for R_PEIMPORT entries (emitted by the assembler from
// -dynlink GOT references). Each unique target symbol — provided the
// host EXE actually defines it — is rebranded
//
//	SymType     = SDYNIMPORT
//	Dynimplib   = <hostExe basename>
//	Extname     = <full Go symbol name>
//
// initdynimport then automatically allocates a .windynamic IAT slot
// per such symbol, and addimports emits a PE Import Directory entry
// targeting the host EXE. The R_PEIMPORT resolver in relocsym computes
// a PC-relative displacement from the call site to that IAT slot —
// exactly the encoding the OS PE loader fills in at LoadLibrary time.
//
// Symbols whose target the host does NOT define, or that
// pluginShouldKeepLocal excludes (link-internal helpers, per-module
// metadata, etc.), are left alone. Their R_PEIMPORT relocs will be
// resolved against the plugin's own copy by the standard PC-rel math
// — equivalent to the pre-2c behaviour for those specific symbols.
func peMarkPluginImports(ctxt *Link) {
	if ctxt.BuildMode != BuildModePlugin {
		return
	}
	if ctxt.HeadType != objabi.Hwindows {
		return
	}
	if buildcfg.GOARCH != "amd64" {
		return
	}

	gs, err := loadPluginHostSidecar(ctxt)
	if err != nil {
		Exitf("%v", err)
	}

	hostBase := filepath.Base(*flagPluginHost)
	hostSyms := gs.indexSymtab()
	ldr := ctxt.loader

	// Per host-shared symbol name, lazily create a synthetic SDYNIMPORT
	// stub. We then rewrite every R_PEIMPORT reloc that targeted the
	// plugin's local definition to point at this stub instead. The
	// original function body remains in the plugin's text (unreachable
	// in practice — only R_PEIMPORT relocs referenced it), so it has
	// no FuncInfo/SEH/DWARF surprises for the rest of the linker.
	stubs := make(map[string]loader.Sym)
	stubFor := func(name string) loader.Sym {
		if s, ok := stubs[name]; ok {
			return s
		}
		stubName := "go:peimport." + name
		su := ldr.CreateSymForUpdate(stubName, 0)
		su.SetType(sym.SDYNIMPORT)
		su.SetReachable(true)
		ldr.SetSymDynimplib(su.Sym(), hostBase)
		ldr.SetSymExtname(su.Sym(), name)
		stubs[name] = su.Sym()
		return su.Sym()
	}

	checked := make(map[loader.Sym]int8) // -1 skip, +1 redirect-as-stub
	classify := func(rs loader.Sym) int8 {
		if v, ok := checked[rs]; ok {
			return v
		}
		v := int8(-1)
		defer func() { checked[rs] = v }()
		name := ldr.SymName(rs)
		if name == "" {
			return v
		}
		if _, ok := hostSyms[name]; !ok {
			return v
		}
		t := ldr.SymType(rs)
		if pluginShouldKeepLocal(name, t) {
			return v
		}
		if t == sym.SDYNIMPORT || t == sym.SHOSTOBJ || t == sym.SUNDEFEXT {
			return v
		}
		switch {
		case t.IsText():
			// Code symbols: redirect refs AND replace body with JMP-via-IAT thunk.
			v = +1
		case t == sym.SRODATA, t == sym.STYPE,
			sym.SNOPTRDATA <= t && t <= sym.SNOPTRBSS:
			// Data symbols (type descriptors, runtime.writeBarrier,
			// runtime.memstats, etc.) the compiler reaches via -dynlink
			// GOT loads. The redirect repoints the IAT slot at the host's
			// definition; the plugin's local copy is left untouched
			// (still consulted by direct R_PCREL relocs from the plugin's
			// own runtime copy, which we deliberately do NOT rewrite —
			// otherwise typelinks/itabs/pclntab would lose their anchors).
			v = +1
		}
		return v
	}

	var redirected, skipped int
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) {
			continue
		}
		// Cheap pre-scan: read relocs without cloning the sym to external
		// (MakeSymbolUpdater clones, which strips SymFlagGoType/Typelink and
		// breaks typelink/itab generation later — see Phase 3 in
		// /memories/session/plan.md).
		relocs := ldr.Relocs(s)
		needRewrite := false
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			if r.Type() != objabi.R_PEIMPORT {
				continue
			}
			rs := r.Sym()
			if rs == 0 {
				continue
			}
			// We rewrite on TWO occasions:
			//   (a) classify >= 0: redirect to host's IAT stub.
			//   (b) classify  < 0: target is plugin-local. The assembler
			//       emitted MOVQ-from-GOT (load address from indirection
			//       slot); since the symbol lives in the same image we
			//       must rewrite MOVQ → LEAQ and turn the R_PEIMPORT into
			//       a plain R_PCREL — same optimization the Linux/amd64
			//       linker performs for R_X86_64_GOTPCRELX.
			needRewrite = true
			break
		}
		if !needRewrite {
			continue
		}
		// Now clone and rewrite.
		su := ldr.MakeSymbolUpdater(s)
		data := su.Data()
		relocs = su.Relocs()
		writableEnsured := false
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			if r.Type() != objabi.R_PEIMPORT {
				continue
			}
			rs := r.Sym()
			if rs == 0 {
				continue
			}
			c := classify(rs)
			if c >= 0 {
				su.SetRelocSym(ri, stubFor(ldr.SymName(rs)))
				redirected++
				continue
			}
			// Local symbol: MOVQ → LEAQ, R_PEIMPORT → R_PCREL.
			off := int(r.Off())
			if off < 2 || data[off-2] != 0x8b {
				// Not a plain MOVQ-from-GOT. Leave as R_PEIMPORT and let
				// the PC-rel resolver handle it; this still produces a
				// disp pointing at the symbol's address, which is
				// correct for instructions that legitimately read 8
				// bytes from there (none today, but be safe).
				skipped++
				continue
			}
			if !writableEnsured {
				su.MakeWritable()
				data = su.Data()
				writableEnsured = true
			}
			data[off-2] = 0x8d // MOVQ → LEAQ
			su.SetRelocType(ri, objabi.R_PCREL)
			skipped++
		}
	}

	if ctxt.Debugvlog > 0 {
		ctxt.Logf("plugin: host=%s pkgs=%d host-shared-stubs=%d redirected-relocs=%d skipped=%d\n",
			*flagPluginHost, len(gs.Pkgs), len(stubs), redirected, skipped)
	}

	// Phase 5: replace each host-shared text symbol's body with a 6-byte
	// JMP-via-IAT thunk so the plugin's local copy of e.g. runtime.mallocgc
	// trampolines to the host's real implementation. Without this, direct
	// R_CALL relocs from the plugin's own runtime copy hit the local body,
	// which uses the plugin's uninitialized mheap/allp/g0 and crashes.
	//
	// Layout: FF 25 00 00 00 00  ; JMP qword ptr [rip+0]
	// with an R_PEIMPORT reloc at offset 2 (siz=4) targeting the SDYNIMPORT
	// stub for this sym. The PE loader fills the IAT slot with the host's
	// real function address; the JMP indirect through IAT lands there.
	//
	// Original FuncInfo / pclntab / DWARF auxes for these syms become stale
	// (size shrinks to 6) but are never consulted at runtime because the
	// thunk never appears on a Go stack — control transfers immediately to
	// the host's text section, where the host's pclntab governs.
	var thunked int
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) {
			continue
		}
		if classify(s) < 0 {
			continue
		}
		if !ldr.SymType(s).IsText() {
			// Data symbols (type:* etc.) must keep their original body so
			// typelinks / itabs / pclntab references resolve correctly;
			// only their R_PEIMPORT loaders get redirected to the IAT.
			continue
		}
		name := ldr.SymName(s)
		stub := stubFor(name)
		su := ldr.MakeSymbolUpdater(s)
		su.SetData([]byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00})
		su.SetSize(6)
		su.ResetRelocs()
		rel, _ := su.AddRel(objabi.R_PEIMPORT)
		rel.SetSym(stub)
		rel.SetOff(2)
		rel.SetSiz(4)
		thunked++
	}
	if ctxt.Debugvlog > 0 {
		ctxt.Logf("plugin: thunked %d host-shared text syms\n", thunked)
	}
}

// pluginShouldKeepLocal reports whether a symbol must be defined in the
// plugin DLL itself rather than imported from the host, even when a
// same-named symbol exists in the host. These are typically per-module
// metadata that the runtime expects to have its own copy of per plugin.
func pluginShouldKeepLocal(name string, t sym.SymKind) bool {
	switch name {
	case "runtime.firstmoduledata",
		"local.pluginmoduledata",
		"go:link.thispluginpath",
		"go:link.pkghashes",
		"go:link.addmoduledata",
		"go:link.addmoduledatainit":
		return true
	}
	// All link-internal symbols must remain local.
	if len(name) > 8 && name[:8] == "go:link." {
		return true
	}
	if len(name) > 6 && name[:6] == "local." {
		return true
	}
	return false
}

// peAppendHostExports runs from inside addexports(), after deadcode
// and all reachability passes. For windows host EXEs that import
// the "plugin" package, it appends every reachable Go symbol to the
// dexport list (deduping against syms already exported via
// cgo_export_dynamic). The PE export table emitted afterwards then
// covers every symbol a plugin could try to import via GetProcAddress.
func peAppendHostExports(ctxt *Link) {
	if ctxt.HeadType != objabi.Hwindows {
		return
	}
	if ctxt.BuildMode == BuildModePlugin {
		return
	}
	if ctxt.LibraryByPkg["plugin"] == nil {
		return
	}
	if buildcfg.GOARCH != "amd64" {
		return
	}
	ldr := ctxt.loader
	already := make(map[loader.Sym]bool, len(dexport))
	for _, s := range dexport {
		already[s] = true
	}
	added := 0
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if already[s] {
			continue
		}
		if !ldr.AttrReachable(s) {
			continue
		}
		name := ldr.SymName(s)
		if name == "" {
			continue
		}
		if pluginShouldKeepLocal(name, ldr.SymType(s)) {
			continue
		}
		t := ldr.SymType(s)
		switch {
		case t.IsText():
			// Skip non-ABIInternal text symbols (e.g. ABI0 wrappers
			// generated for asm-callable entry points) when an
			// ABIInternal sibling with the same name exists. Plugins
			// compiled as Go code call runtime functions through the
			// ABIInternal calling convention (args in registers); if
			// we exported both, the PE export table would contain two
			// entries with identical names and the plugin's IAT could
			// resolve to the wrong (stack-based) wrapper, producing a
			// silent ABI mismatch and a corrupted first argument.
			if ldr.SymVersion(s) != sym.SymVerABIInternal &&
				ldr.SymVersion(s) < sym.SymVerStatic {
				if s2 := ldr.Lookup(name, sym.SymVerABIInternal); s2 != 0 &&
					ldr.SymType(s2).IsText() && ldr.AttrReachable(s2) {
					continue
				}
			}
		case t == sym.SRODATA, t == sym.STYPE, t == sym.SSTRING, t == sym.SGOSTRING,
			t == sym.SGOFUNC, t == sym.SFUNCTAB, t == sym.STYPELINK, t == sym.SITABLINK:
		case t == sym.SDATA, t == sym.SNOPTRDATA, t == sym.SINITARR:
		case t == sym.SBSS, t == sym.SNOPTRBSS:
		default:
			continue
		}
		if ldr.SymExtname(s) != name {
			// mangleTypeSym may have rewritten Extname to a short hash;
			// plugin DLLs import the full Go name, so force the export
			// name back. Safe because we never feed these to an external
			// linker — internal linker only.
			ldr.SetSymExtname(s, name)
		}
		dexport = append(dexport, s)
		already[s] = true
		added++
	}
	if ctxt.Debugvlog > 0 {
		ctxt.Logf("plugin host: appended %d Go symbols to PE export table\n", added)
	}
	// PE name pointer table must be lexicographically sorted by export
	// name for GetProcAddress's binary search to work.
	sort.Slice(dexport, func(i, j int) bool { return ldr.SymExtname(dexport[i]) < ldr.SymExtname(dexport[j]) })
}
