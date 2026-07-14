package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"combinedtunnel/mobilebridge"
	"fmt"
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

//export Start
func Start(configJSON *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	sessionID, err := mobilebridge.Start(C.GoString(configJSON))
	if err != nil {
		return errstr(err)
	}
	return cstr(sessionID)
}

//export StartFromUrl
func StartFromUrl(configURL *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	sessionID, err := mobilebridge.StartFromUrl(C.GoString(configURL))
	if err != nil {
		return errstr(err)
	}
	return cstr(sessionID)
}

//export StartOlcRTC
func StartOlcRTC(roomID *C.char, keyHex *C.char, socksPort C.int, socksUser *C.char, socksPass *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	sessionID, err := mobilebridge.StartOlcRTC(
		C.GoString(roomID),
		C.GoString(keyHex),
		int(socksPort),
		C.GoString(socksUser),
		C.GoString(socksPass),
	)
	if err != nil {
		return errstr(err)
	}
	return cstr(sessionID)
}

//export Stop
func Stop(sessionID *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	return errstr(mobilebridge.Stop(C.GoString(sessionID)))
}

//export StopAll
func StopAll() (ret *C.char) {
	defer recoverCStr(&ret)
	return errstr(mobilebridge.StopAll())
}

// StartCore is the clean single-session entrypoint for the GreenPass plugin.
// Returns an empty string on success or "error: ..." on failure, matching the
// VlessCore C-ABI contract (empty == success; the caller frees the returned string).
// Only the olcrtc engine is supported. The JSON "engine" field may be omitted
// or set to "olcrtc".
//
//export StartCore
func StartCore(configJSON *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	return errstr(mobilebridge.StartSingle(C.GoString(configJSON)))
}

// StopCore stops the single active session. Safe to call when nothing is running.
//
//export StopCore
func StopCore() {
	defer func() {
		_ = recover()
	}()
	_ = mobilebridge.StopSingle()
}

//export IsRunning
func IsRunning(sessionID *C.char) (ret C.int) {
	defer func() {
		if recover() != nil {
			ret = 0
		}
	}()
	if mobilebridge.IsRunning(C.GoString(sessionID)) {
		return 1
	}
	return 0
}

//export Version
func Version() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(mobilebridge.Version())
}

//export ValidateConfig
func ValidateConfig(configJSON *C.char) (ret *C.char) {
	defer recoverCStr(&ret)
	return errstr(mobilebridge.ValidateConfig(C.GoString(configJSON)))
}

//export SetLogLevel
func SetLogLevel(level *C.char) {
	defer func() {
		_ = recover()
	}()
	mobilebridge.SetLogLevel(C.GoString(level))
}

//export LastLog
func LastLog() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(mobilebridge.LastLog())
}

//export LastError
func LastError() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(mobilebridge.LastError())
}

//export GetStatusJSON
func GetStatusJSON() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(mobilebridge.StatusJSON())
}

//export GetLogsJSON
func GetLogsJSON() (ret *C.char) {
	defer recoverCStr(&ret)
	return cstr(mobilebridge.LogsJSON())
}

//export FreeCString
func FreeCString(ptr *C.char) {
	defer func() {
		_ = recover()
	}()
	C.free(unsafe.Pointer(ptr))
}

func main() {}
