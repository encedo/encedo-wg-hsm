package main

import (
	"fmt"
	"runtime"
	"unicode/utf16"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"
	"golang.org/x/sys/windows"
)

// chooserOwner is the window the chooser is modal to.
type chooserOwner = uintptr

func nativeOwner(w fyne.Window) chooserOwner {
	var hwnd uintptr
	if nw, ok := w.(driver.NativeWindow); ok {
		nw.RunNative(func(ctx any) {
			if c, ok := ctx.(driver.WindowsWindowContext); ok {
				hwnd = c.HWND
			}
		})
	}
	return hwnd
}

var (
	comdlg32                 = windows.NewLazySystemDLL("comdlg32.dll")
	procGetOpenFileNameW     = comdlg32.NewProc("GetOpenFileNameW")
	procCommDlgExtendedError = comdlg32.NewProc("CommDlgExtendedError")
)

// openFileName is OPENFILENAMEW. Go lays the fields out as C does on every
// Windows target this builds for, so the size is taken rather than written.
type openFileName struct {
	structSize    uint32
	owner         uintptr
	instance      uintptr
	filter        *uint16
	customFilter  *uint16
	maxCustFilter uint32
	filterIndex   uint32
	file          *uint16
	maxFile       uint32
	fileTitle     *uint16
	maxFileTitle  uint32
	initialDir    *uint16
	title         *uint16
	flags         uint32
	fileOffset    uint16
	fileExtension uint16
	defExt        *uint16
	custData      uintptr
	hook          uintptr
	templateName  *uint16
	reserved      uintptr
	reservedDW    uint32
	flagsEx       uint32
}

const (
	ofnNoChangeDir     = 0x00000008
	ofnPathMustExist   = 0x00000800
	ofnFileMustExist   = 0x00001000
	ofnExplorer        = 0x00080000
	ofnDontAddToRecent = 0x02000000
)

// nativeOpen asks for one file with the common dialog every Windows program
// uses. It runs on a locked thread with COM initialised, which the Explorer
// style dialog expects of its caller.
//
// Not added to the recent-documents list: the file holds a private key that
// this client is about to leave behind, and a shortcut to it in Quick Access is
// not something anybody would expect an import to leave.
func nativeOpen(owner chooserOwner, title string) (path string, handled bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); err == nil {
		defer windows.CoUninitialize()
	}

	// Pairs of name and pattern, each ending in a NUL, the list ending in two.
	filter := utf16.Encode([]rune("WireGuard configuration (*.conf)\x00*.conf\x00All files (*.*)\x00*.*\x00\x00"))
	buf := make([]uint16, windows.MAX_LONG_PATH)
	t, _ := windows.UTF16PtrFromString(title)

	ofn := openFileName{
		owner:       owner,
		filter:      &filter[0],
		filterIndex: 1,
		file:        &buf[0],
		maxFile:     uint32(len(buf)),
		title:       t,
		flags:       ofnExplorer | ofnFileMustExist | ofnPathMustExist | ofnNoChangeDir | ofnDontAddToRecent,
	}
	ofn.structSize = uint32(unsafe.Sizeof(ofn))

	if r, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn))); r != 0 {
		return windows.UTF16ToString(buf), true, nil
	}
	// Zero is a cancel; anything else is the dialog failing, and it says why
	// only as a number from its own table - not a system error code, so not an
	// Errno, which would print some unrelated system message for it.
	if code, _, _ := procCommDlgExtendedError.Call(); code != 0 {
		return "", true, fmt.Errorf("common dialog error 0x%04x", code)
	}
	return "", true, nil
}
