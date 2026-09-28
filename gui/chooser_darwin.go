package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>
#include <stdlib.h>
#include <string.h>

// chooseFile runs the system open panel and returns the chosen path, which the
// caller frees, or NULL when the panel was cancelled.
//
// AppKit panels belong to the main thread. The window's main thread is Fyne's
// event loop, which drains the main dispatch queue while it waits for events,
// so the panel is sent there and this thread waits for the answer.
static char *chooseFile(const char *message) {
	__block char *out = NULL;
	NSString *m = [NSString stringWithUTF8String:message];
	void (^ask)(void) = ^{
		NSOpenPanel *p = [NSOpenPanel openPanel];
		p.message = m;
		p.prompt = @"Import";
		p.canChooseFiles = YES;
		p.canChooseDirectories = NO;
		p.allowsMultipleSelection = NO;
		[NSApp activateIgnoringOtherApps:YES];
		if ([p runModal] == NSModalResponseOK && p.URL != nil) {
			out = strdup(p.URL.fileSystemRepresentation);
		}
	};
	if ([NSThread isMainThread]) {
		ask();
	} else {
		dispatch_sync(dispatch_get_main_queue(), ask);
	}
	return out;
}
*/
import "C"

import (
	"unsafe"

	"fyne.io/fyne/v2"
)

// chooserOwner is unused on macOS: the panel is application-modal, which is as
// attached to the window as a one-window program needs.
type chooserOwner = struct{}

func nativeOwner(fyne.Window) chooserOwner { return chooserOwner{} }

// nativeOpen asks for one file with NSOpenPanel - the Finder's chooser, with the
// sidebar, recents and search a person already knows.
//
// Not filtered to .conf. The panel has no "all files" switch to fall back on the
// way the Linux and Windows choosers do, so a filter here would be a rule
// rather than a suggestion, and a file somebody was emailed is as likely to be
// called vpn.txt.
func nativeOpen(_ chooserOwner, title string) (path string, handled bool, err error) {
	m := C.CString(title)
	defer C.free(unsafe.Pointer(m))
	p := C.chooseFile(m)
	if p == nil {
		return "", true, nil
	}
	defer C.free(unsafe.Pointer(p))
	return C.GoString(p), true, nil
}
