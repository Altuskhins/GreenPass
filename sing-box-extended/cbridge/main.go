package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"singboxextended/unifiedbridge"
	"unsafe"
)

func cstr(value string) *C.char {
	return C.CString(value)
}

func errstr(err error) *C.char {
	if err != nil {
		return C.CString("error: " + err.Error())
	}
	return C.CString("")
}

func recoverCStr(ret **C.char) {
	if r := recover(); r != nil {
		*ret = cstr(fmt.Sprintf("error: panic: %v", r))
	}
}

// StartCore is the clean single-session entrypoint for the GreenPass plugin.
// It accepts a sing-box JSON config and starts exactly one core instance (any
// running instance is stopped first). Returns an empty string on success or
// "error: ..." on failure, matching the VlessCore C-ABI contract (empty ==
// success; the caller frees the returned string with FreeCString).
//
//export StartCore
func StartCore(configJSON *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	return errstr(unifiedbridge.Start(C.GoString(configJSON)))
}

// StopCore stops the single active session. Safe to call when nothing is running.
//
//export StopCore
func StopCore() {
	defer func() {
		_ = recover()
	}()
	_ = unifiedbridge.Stop()
}

// IsRunning reports whether the single session is currently running (1) or not (0).
//
//export IsRunning
func IsRunning() (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = 0
		}
	}()
	if unifiedbridge.IsRunning() {
		return 1
	}
	return 0
}

// Version returns the bridge build version.
//
//export Version
func Version() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(unifiedbridge.Version())
}

// ValidateConfig parses and structurally validates a sing-box JSON config
// without starting anything. Returns "" on success or "error: ...".
//
//export ValidateConfig
func ValidateConfig(configJSON *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	return errstr(unifiedbridge.ValidateConfig(C.GoString(configJSON)))
}

// LastLog returns the latest log or state message observed by the bridge.
//
//export LastLog
func LastLog() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(unifiedbridge.LastLog())
}

// LastError returns the latest error observed by the bridge.
//
//export LastError
func LastError() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(unifiedbridge.LastError())
}

// GetStatusJSON returns the latest core lifecycle status as a JSON object.
//
//export GetStatusJSON
func GetStatusJSON() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(unifiedbridge.StatusJSON())
}

// GetLogsJSON returns the latest log entries as a JSON array (oldest first).
//
//export GetLogsJSON
func GetLogsJSON() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(unifiedbridge.LogsJSON())
}

//export CurrentEngine
func CurrentEngine() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(unifiedbridge.CurrentEngine())
}

// FreeCString releases a string previously returned by any exported function.
// The caller MUST call this for every non-nil returned *C.char to avoid leaks.
//
//export FreeCString
func FreeCString(ptr *C.char) {
	defer func() {
		_ = recover()
	}()
	C.free(unsafe.Pointer(ptr))
}

func main() {}
