package main

import "time"

// A scenario is the life of a session written down: the states arrive in the
// order and roughly the rhythm they would on real hardware, without anybody
// having to know which debug button produces which one.
//
// One definition, two consumers. Run with -scenario it plays out in the window
// so somebody can watch the whole thing once and say whether it makes sense.
// The render test walks the same list and captures a frame per step, so the
// flow can be reviewed as a strip without running anything at all. Two
// descriptions of the same sequence would drift; this one cannot.
type step struct {
	after time.Duration // wait before acting, from the end of the previous step
	what  string        // what a viewer is meant to notice
	do    func(*fakeSession)
}

// The order matters more than the timings. Connect happens before the first
// failover so a peer changing under a working tunnel reads as a change; expiry
// comes last because it is the state people are least prepared for, and it
// arrives after they have settled into thinking the tunnel is simply up.
var scenario = []step{
	{0, "nothing plugged in", func(f *fakeSession) { f.setModulePresent(false) }},
	{2500, "the module appears", func(f *fakeSession) { f.setModulePresent(true) }},
	{2000, "connecting", func(f *fakeSession) { f.connectWith("passphrase") }},
	{6000, "the active peer stops answering, and failover moves", (*fakeSession).triggerFailover},
	{6000, "the session is running out", func(f *fakeSession) { f.expireIn(4 * time.Minute) }},
	{4000, "and it ends - no renewal, by design", func(f *fakeSession) { f.expireNow() }},
	{3500, "reconnecting after the end", func(f *fakeSession) { f.connectWith("passphrase") }},
	{5000, "the module is pulled out", func(f *fakeSession) { f.setModulePresent(false) }},
}

// play runs the scenario against a live session. Errors from Connect are
// ignored: the scenario is a script, and a script that has diverged from the
// state machine is a bug the window will show anyway.
func (f *fakeSession) play(announce func(string)) {
	for _, s := range scenario {
		time.Sleep(s.after * time.Millisecond / time.Millisecond)
		if announce != nil {
			announce(s.what)
		}
		s.do(f)
	}
}
