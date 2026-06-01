// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package plugin

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Windows plugin loading mirrors the dlopen-based path used on
// Linux/Darwin/FreeBSD. The DLL is built with -buildmode=plugin and
// -pluginhost=<host>.exe, which causes its runtime/stdlib symbols to
// resolve to the host EXE via the PE import table. Loading the DLL
// triggers a TLS callback that calls runtime.addmoduledata, attaching
// the plugin's moduledata to the host's firstmoduledata chain.
// plugin_lastmoduleinit (in package runtime) then completes type
// unification, itab merge, and surfaces the plugin's symbol table.

func open(name string) (*Plugin, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return nil, errors.New(`plugin.Open("` + name + `"): ` + err.Error())
	}

	pluginsMu.Lock()
	if p := plugins[abs]; p != nil {
		pluginsMu.Unlock()
		if p.err != "" {
			return nil, errors.New(`plugin.Open("` + name + `"): ` + p.err + ` (previous failure)`)
		}
		<-p.loaded
		return p, nil
	}

	dll, err := syscall.LoadDLL(abs)
	if err != nil {
		pluginsMu.Unlock()
		return nil, errors.New(`plugin.Open("` + name + `"): ` + err.Error())
	}

	// Manually resolve the plugin DLL's PE imports that target the
	// running host EXE. The Windows loader does not bind imports from
	// a non-DLL EXE module (host.exe is IMAGE_FILE_EXECUTABLE_IMAGE,
	// not IMAGE_FILE_DLL), so each IAT slot is left containing the
	// hint/name RVA. We patch them ourselves with GetProcAddress on
	// the running EXE handle.
	if err := patchHostImports(dll); err != nil {
		pluginsMu.Unlock()
		return nil, errors.New(`plugin.Open("` + name + `"): patching host imports: ` + err.Error())
	}

	// LoadDLL on windows does not register the plugin's moduledata in
	// the host runtime's firstmoduledata chain (there is no
	// dlopen(RTLD_GLOBAL) equivalent). Instead the plugin DLL exports
	// its local.pluginmoduledata symbol; we look it up and pass it to
	// runtime.pluginAddmoduledata host-side. lastmoduleinit() below
	// then sees a fresh moduledata at the tail of the chain.
	mdProc, err := dll.FindProc("go_pluginmoduledata")
	if err != nil {
		pluginsMu.Unlock()
		return nil, errors.New(`plugin.Open("` + name + `"): plugin DLL does not export go_pluginmoduledata: ` + err.Error())
	}
	pluginAddmoduledata(mdProc.Addr())

	displayName := name
	if ext := filepath.Ext(displayName); ext == ".dll" || ext == ".so" {
		displayName = displayName[:len(displayName)-len(ext)]
	}
	if plugins == nil {
		plugins = make(map[string]*Plugin)
	}

	pluginpath, syms, initTasks, errstr := lastmoduleinit()
	if errstr != "" {
		plugins[abs] = &Plugin{
			pluginpath: pluginpath,
			err:        errstr,
		}
		pluginsMu.Unlock()
		return nil, errors.New(`plugin.Open("` + name + `"): ` + errstr)
	}

	p := &Plugin{
		pluginpath: pluginpath,
		loaded:     make(chan struct{}),
	}
	plugins[abs] = p
	pluginsMu.Unlock()

	// Skip init tasks for packages whose `.inittask` symbol is also
	// exported from the host EXE: those packages are host-shared (their
	// init has already run during host startup), and re-running them in
	// the plugin would corrupt host runtime state (e.g. a duplicate
	// forcegchelper goroutine from runtime.init.7). For the remaining
	// plugin-only packages (the user's own code, plus any imports the
	// host did not pull in), doInit must still run.
	if hostMod, herr := getModuleHandleNull(); herr == nil {
		for _, t := range initTasks {
			if t == nil {
				continue
			}
			nfns := *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(t)) + 4))
			if nfns == 0 {
				continue
			}
			firstPC := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(t)) + 8))
			fn := runtime.FuncForPC(firstPC)
			if fn == nil {
				continue
			}
			name := fn.Name() // e.g. "fmt.init.0" or "runtime.init.7"
			i := strings.LastIndex(name, ".init")
			if i < 0 {
				continue
			}
			pkg := name[:i]
			if addr, err := syscall.GetProcAddress(hostMod, pkg+"..inittask"); err == nil && addr != 0 {
				*(*uint32)(unsafe.Pointer(t)) = 2 // mark as already done
			}
		}
	}
	doInit(initTasks)

	updatedSyms := map[string]any{}
	for symName, sym := range syms {
		isFunc := symName[0] == '.'
		if isFunc {
			delete(syms, symName)
			symName = symName[1:]
		}

		fullName := pluginpath + "." + symName
		proc, err := dll.FindProc(fullName)
		if err != nil {
			return nil, errors.New(`plugin.Open("` + displayName + `"): could not find symbol ` + symName + `: ` + err.Error())
		}
		valp := (*[2]unsafe.Pointer)(unsafe.Pointer(&sym))
		if isFunc {
			addr := proc.Addr()
			(*valp)[1] = unsafe.Pointer(&addr)
		} else {
			(*valp)[1] = unsafe.Pointer(proc.Addr())
		}
		updatedSyms[symName] = sym
	}
	p.syms = updatedSyms

	close(p.loaded)
	return p, nil
}

func lookup(p *Plugin, symName string) (Symbol, error) {
	if s := p.syms[symName]; s != nil {
		return s, nil
	}
	return nil, errors.New("plugin: symbol " + symName + " not found in plugin " + p.pluginpath)
}

var (
	pluginsMu sync.Mutex
	plugins   map[string]*Plugin
)

// lastmoduleinit is defined in package runtime.
func lastmoduleinit() (pluginpath string, syms map[string]any, inittasks []*initTask, errstr string)

// pluginAddmoduledata is defined in package runtime. It registers the
// plugin's local.pluginmoduledata with the host runtime's
// firstmoduledata chain.
//
//go:linkname pluginAddmoduledata runtime.pluginAddmoduledata
func pluginAddmoduledata(md uintptr)

// doInit is defined in package runtime.
//
//go:linkname doInit runtime.doInit
func doInit(t []*initTask)

type initTask struct {
	// fields defined in runtime.initTask. We only handle pointers to an initTask
	// in this package, so the contents are irrelevant.
}

// patchHostImports walks the plugin DLL's PE Import Directory and, for
// every entry whose import-name DLL is the running host EXE's basename,
// resolves each thunk's hint/name with GetProcAddress on the running
// process module and overwrites the IAT slot with the absolute
// function address. This is needed because the Windows loader does not
// bind imports against a non-DLL EXE on its own.
func patchHostImports(dll *syscall.DLL) error {
	hostMod, err := getModuleHandleNull()
	if err != nil {
		return err
	}
	hostExe, err := getModuleBaseName(hostMod)
	if err != nil {
		return err
	}

	base := uintptr(dll.Handle)
	// PE/COFF parsing.
	peOff := *(*int32)(unsafe.Pointer(base + 0x3c))
	// Optional header is at peOff + 4 (sig) + 20 (file header) = peOff + 24.
	// DataDirectory[1] (IMPORT) is at optional + 112 (PE32+).
	dd := base + uintptr(peOff) + 24 + 112
	importRVA := *(*uint32)(unsafe.Pointer(dd + 1*8))
	if importRVA == 0 {
		return nil
	}

	type imgImportDesc struct {
		OriginalFirstThunk uint32
		TimeDateStamp      uint32
		ForwarderChain     uint32
		Name               uint32
		FirstThunk         uint32
	}

	desc := (*imgImportDesc)(unsafe.Pointer(base + uintptr(importRVA)))
	for desc.Name != 0 || desc.OriginalFirstThunk != 0 {
		dllName := cstring(base + uintptr(desc.Name))
		if !equalFold(dllName, hostExe) {
			desc = (*imgImportDesc)(unsafe.Pointer(uintptr(unsafe.Pointer(desc)) + unsafe.Sizeof(*desc)))
			continue
		}
		// Walk the thunk arrays in lock-step. OriginalFirstThunk
		// (Import Lookup Table) is the unmodified hint/name RVAs.
		// FirstThunk (Import Address Table) is what we patch.
		oft := desc.OriginalFirstThunk
		if oft == 0 {
			oft = desc.FirstThunk
		}
		ilt := base + uintptr(oft)
		iat := base + uintptr(desc.FirstThunk)
		// Count slots first to determine size for VirtualProtect.
		slots := uintptr(0)
		for {
			if *(*uint64)(unsafe.Pointer(ilt + slots*8)) == 0 {
				break
			}
			slots++
		}
		var oldProtect uint32
		if err := virtualProtect(iat, slots*8, 0x04 /* PAGE_READWRITE */, &oldProtect); err != nil {
			return err
		}
		broken := false
		var missingName string
		for i := uintptr(0); i < slots; i++ {
			lookup := *(*uint64)(unsafe.Pointer(ilt + i*8))
			if lookup&(1<<63) != 0 {
				continue // ordinal — leave alone
			}
			hintNameRVA := uint32(lookup)
			procName := cstring(base + uintptr(hintNameRVA) + 2)
			addr, _ := syscall.GetProcAddress(hostMod, procName)
			if addr == 0 {
				broken = true
				missingName = procName
				break
			}
			*(*uintptr)(unsafe.Pointer(iat + i*8)) = addr
		}
		_ = virtualProtect(iat, slots*8, oldProtect, &oldProtect)
		if broken {
			return errors.New("host EXE does not export imported symbol: " + missingName)
		}
		desc = (*imgImportDesc)(unsafe.Pointer(uintptr(unsafe.Pointer(desc)) + unsafe.Sizeof(*desc)))
	}
	return nil
}

var (
	modKernel32        = syscall.NewLazyDLL("kernel32.dll")
	procVirtualProtect = modKernel32.NewProc("VirtualProtect")
)

func virtualProtect(addr, size uintptr, newProtect uint32, oldProtect *uint32) error {
	r1, _, e := syscall.SyscallN(procVirtualProtect.Addr(), addr, size, uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)))
	if r1 == 0 {
		return e
	}
	return nil
}

func cstring(p uintptr) string {
	var n int
	for *(*byte)(unsafe.Pointer(p + uintptr(n))) != 0 {
		n++
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = *(*byte)(unsafe.Pointer(p + uintptr(i)))
	}
	return string(b)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

var (
	procGetModuleHandleW   = modKernel32.NewProc("GetModuleHandleW")
	procGetModuleFileNameW = modKernel32.NewProc("GetModuleFileNameW")
)

func getModuleHandleNull() (syscall.Handle, error) {
	r1, _, e := syscall.SyscallN(procGetModuleHandleW.Addr(), 0)
	if r1 == 0 {
		return 0, e
	}
	return syscall.Handle(r1), nil
}

func getModuleBaseName(h syscall.Handle) (string, error) {
	var buf [syscall.MAX_PATH]uint16
	r1, _, e := syscall.SyscallN(procGetModuleFileNameW.Addr(), uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r1 == 0 {
		return "", e
	}
	full := syscall.UTF16ToString(buf[:r1])
	for i := len(full) - 1; i >= 0; i-- {
		if full[i] == '\\' || full[i] == '/' {
			return full[i+1:], nil
		}
	}
	return full, nil
}
