module ircmsg

// Casemapping is how a server folds nicknames and channel names before comparing them
// (the CASEMAPPING ISUPPORT token).
pub enum Casemapping {
	ascii
	rfc1459
	strict_rfc1459
}

// str returns the name advertised in ISUPPORT.
pub fn (c Casemapping) str() string {
	return match c {
		.ascii { 'ascii' }
		.rfc1459 { 'rfc1459' }
		.strict_rfc1459 { 'strict-rfc1459' }
	}
}

// fold returns `name` folded to lower case under the casemapping.
pub fn (c Casemapping) fold(name string) string {
	mut out := []u8{len: name.len}
	for i, b in name {
		out[i] = match true {
			b >= `A` && b <= `Z` { b + 32 }
			c != .ascii && b >= `[` && b <= `]` { b + 32 }
			c == .rfc1459 && b == `^` { `~` }
			else { b }
		}
	}
	return out.bytestr()
}
