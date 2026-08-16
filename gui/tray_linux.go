package main

import "github.com/godbus/dbus/v5"

// A tray icon on Linux is not something the desktop necessarily has.
//
// The toolkit will accept a tray menu on any desktop and register it over
// D-Bus, and registration is where it fails - asynchronously, into the log,
// with nothing returned to us:
//
//	systray error: failed to register: No such method "RegisterStatusNotifierItem"
//
// Stock GNOME is that case: it dropped the tray years ago and only has one if
// somebody installed an extension. So the window believed it had a tray, offered
// "keep it in the tray" when somebody closed it, hid itself - and there was
// nowhere to click. A hidden window with no tray is a live tunnel and a
// credential nobody can reach, which is worse than any of the outcomes the
// dialogue was choosing between.
//
// So the question is asked before the offer is made - and it has to be the right
// question. Measured on this desktop:
//
//	$ busctl --user list | grep StatusNotifier
//	org.kde.StatusNotifierWatcher ... gnome-shell
//	$ busctl --user get-property ... IsStatusNotifierHostRegistered
//	Failed: No such property "IsStatusNotifierHostRegistered"
//
// gnome-shell owns the name and advertises the interface, introspection and all,
// while implementing none of it. So "is the name owned" answers yes on a desktop
// with no tray whatsoever, which is how the first attempt at this changed
// nothing.
//
// Asking whether a *host* is registered is both the question that matters - a
// watcher with no host is a tray nobody draws - and the one that fails loudly
// against a shell that only looks like one.

const (
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = "/StatusNotifierWatcher"
	hostRegProp  = "org.kde.StatusNotifierWatcher.IsStatusNotifierHostRegistered"
	nameHasOwner = "org.freedesktop.DBus.NameHasOwner"
)

func trayAvailable() bool {
	conn, err := dbus.SessionBus()
	if err != nil {
		return false
	}
	var owned bool
	if err := conn.BusObject().Call(nameHasOwner, 0, watcherName).Store(&owned); err != nil || !owned {
		return false
	}

	v, err := conn.Object(watcherName, watcherPath).GetProperty(hostRegProp)
	if err != nil {
		// Declared and not implemented: something is holding the name that
		// cannot host anything.
		return false
	}
	registered, ok := v.Value().(bool)
	return ok && registered
}
