//go:build windows

// Command winsmoke loads the Windows plugin DLL the way the CLIProxyAPI
// Windows loader does (internal/pluginhost/loader_windows.go): LoadDLL,
// cliproxy_plugin_init, one call, free_buffer, shutdown.
//
// Usage: go run ./scripts/winsmoke <path-to-dll>
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type buffer struct {
	ptr unsafe.Pointer
	len uintptr
}

type pluginAPI struct {
	abiVersion uint32
	call       uintptr
	freeBuffer uintptr
	shutdown   uintptr
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: winsmoke <dll>")
	}
	dll, err := syscall.LoadDLL(os.Args[1])
	if err != nil {
		fail("load: %v", err)
	}
	initProc, err := dll.FindProc("cliproxy_plugin_init")
	if err != nil {
		fail("find cliproxy_plugin_init: %v", err)
	}
	var api pluginAPI
	rc, _, _ := initProc.Call(0, uintptr(unsafe.Pointer(&api)))
	if rc != 0 {
		fail("cliproxy_plugin_init returned %d", rc)
	}
	if api.abiVersion != 1 || api.call == 0 || api.freeBuffer == 0 || api.shutdown == 0 {
		fail("bad plugin api: %+v", api)
	}

	method, _ := syscall.BytePtrFromString("frontend_auth.identifier")
	var resp buffer
	rc, _, _ = syscall.SyscallN(api.call, uintptr(unsafe.Pointer(method)), 0, 0, uintptr(unsafe.Pointer(&resp)))
	if rc != 0 || resp.ptr == nil || resp.len == 0 {
		fail("frontend_auth.identifier: rc=%d len=%d", rc, resp.len)
	}
	out := string(unsafe.Slice((*byte)(resp.ptr), resp.len))
	syscall.SyscallN(api.freeBuffer, uintptr(resp.ptr), resp.len)
	syscall.SyscallN(api.shutdown)
	fmt.Println("abi_version=1, frontend_auth.identifier ->", out)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "winsmoke: "+format+"\n", args...)
	os.Exit(1)
}
