package daemon

// Principal is who is on the other end of a connection, in whatever terms the
// platform can answer without being told.
//
// It used to be a uid, which is what Linux answers and what the rules here are
// written in terms of: a tunnel belongs to whoever started it, and only they may
// stop or renew it. Windows answers a SID, which is not a number and not
// comparable to one, and the rules do not care — they only ever ask whether two
// answers are the same.
//
// So it is an opaque string with a prefix naming what produced it. The prefix is
// not decoration: it stops "uid:0" and a SID that happened to render as "0" from
// ever being the same principal, and it makes a log line say which kind of
// identity the platform gave.
//
// It is deliberately not a struct. It goes in comparisons and in log lines and
// nowhere else, and a comparable value that prints itself is the whole
// requirement.
type Principal string

// Anonymous is the zero value, and never equal to a real principal because
// every platform's answer carries a prefix and this does not. A connection whose
// owner could not be determined is refused before it can be compared with
// anything, so this exists to make that refusal impossible to skip by accident
// rather than to be used.
const Anonymous Principal = ""

func (p Principal) String() string {
	if p == Anonymous {
		return "an unidentified caller"
	}
	return string(p)
}
