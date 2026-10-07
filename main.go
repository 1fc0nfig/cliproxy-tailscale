// Command tailscale-identity is a CLIProxyAPI dynamic-library plugin.
// Build it with -buildmode=c-shared. The C ABI below mirrors
// CLIProxyAPI internal/pluginhost/loader_unix.go (ABI version 1).
package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"sync"
	"unsafe"

	"github.com/1fc0nfig/cliproxy-tailscale/internal/tsid"
)

const abiVersion uint32 = 1

var (
	pluginOnce sync.Once
	plugin     *tsid.Plugin
)

func getPlugin() *tsid.Plugin {
	pluginOnce.Do(func() { plugin = tsid.NewPlugin(tsid.DefaultDeps(), tsid.OSEnv) })
	return plugin
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, api *C.cliproxy_plugin_api) C.int {
	if api == nil {
		return 1
	}
	// dlopen of the same path returns the same image, so init can run again
	// in one process. Reuse the package state and clear the closed flag.
	p := getPlugin()
	p.Reopen()
	C.store_host_api(host)
	if host != nil {
		tsid.SetLogSink(hostLog)
	}
	api.abi_version = C.uint32_t(abiVersion)
	api.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	api.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	api.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, []byte(`{"ok":false,"error":{"code":"invalid_method","message":"method is required"}}`))
		return 1
	}
	var req []byte
	if request != nil && requestLen > 0 {
		req = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	writeResponse(response, getPlugin().Handle(C.GoString(method), req))
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	// The host frees host_api right after this returns. Detach the log sink
	// first: after SetLogSink(nil) no host call is in flight.
	tsid.SetLogSink(nil)
	C.store_host_api(nil)
	getPlugin().Shutdown()
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

type hostLogRequest struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// hostLog sends one line through the host.log callback.
func hostLog(level, msg string, fields map[string]any) {
	payload, err := json.Marshal(hostLogRequest{Level: level, Message: msg, Fields: fields})
	if err != nil {
		return
	}
	cMethod := C.CString("host.log")
	defer C.free(unsafe.Pointer(cMethod))
	req := (*C.uint8_t)(C.CBytes(payload))
	defer C.free(unsafe.Pointer(req))
	var resp C.cliproxy_buffer
	C.call_host_api(cMethod, req, C.size_t(len(payload)), &resp)
	if resp.ptr != nil {
		C.free_host_buffer(resp.ptr, resp.len)
	}
}
