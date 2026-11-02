// Module ircmsg parses and serializes IRC protocol lines, including the
// IRCv3 message tags (https://ircv3.net/specs/extensions/message-tags).
// It has no dependency on a client or server implementation.
module ircmsg

// max_line_bytes is the RFC 1459 limit of the non-tag part of a line, CR LF included.
pub const max_line_bytes = 512
// max_client_tags_bytes is the limit of the tags a client may send, `@` and the
// trailing space included.
pub const max_client_tags_bytes = 4096
// max_params is the most parameters a message can carry.
pub const max_params = 15

// Tag is one message tag. A tag without a value has an empty `value`.
pub struct Tag {
pub:
	key   string
	value string
}

// Message is one IRC line, without its CR LF.
pub struct Message {
pub mut:
	tags    []Tag
	source  string
	command string
	params  []string
}

// ParseError is returned for lines that are not valid IRC messages.
pub struct ParseError {
	Error
pub:
	reason string
}

// msg returns the reason of the parse error.
pub fn (e ParseError) msg() string {
	return 'invalid IRC message: ${e.reason}'
}

fn parse_error(reason string) IError {
	return ParseError{
		reason: reason
	}
}

// parse parses one line, without its CR LF. It rejects NUL, CR and LF anywhere,
// empty commands and more than `max_params` parameters. The command is upper-cased
// but not checked, so that a server can answer an unknown one. Length limits are
// the caller's job, since they differ between clients and servers (see `split_tags`).
pub fn parse(line string) !Message {
	for c in line {
		if c == 0 || c == `\r` || c == `\n` {
			return parse_error('NUL, CR or LF in line')
		}
	}
	mut rest := line
	mut msg := Message{}
	if rest.starts_with('@') {
		end := rest.index_u8(` `)
		if end < 0 {
			return parse_error('tags without a command')
		}
		msg.tags = parse_tags(rest[1..end])!
		rest = skip_spaces(rest[end..])
	}
	if rest.starts_with(':') {
		end := rest.index_u8(` `)
		if end < 0 {
			return parse_error('source without a command')
		}
		msg.source = rest[1..end]
		if msg.source == '' {
			return parse_error('empty source')
		}
		rest = skip_spaces(rest[end..])
	}
	end := rest.index_u8(` `)
	command := if end < 0 { rest } else { rest[..end] }
	if command == '' {
		return parse_error('empty command')
	}
	msg.command = command.to_upper()
	rest = if end < 0 { '' } else { skip_spaces(rest[end..]) }
	for rest != '' {
		if rest[0] == `:` {
			msg.params << rest[1..]
			break
		}
		sp := rest.index_u8(` `)
		if sp < 0 {
			msg.params << rest
			break
		}
		msg.params << rest[..sp]
		rest = skip_spaces(rest[sp..])
	}
	if msg.params.len > max_params {
		return parse_error('too many parameters')
	}
	return msg
}

// valid_nickname reports whether `nick` is a valid nickname of at most `max_len`
// bytes: ASCII letters, digits and any of - _ [ ] \ ^ { } | `, not starting
// with a digit or `-`.
pub fn valid_nickname(nick string, max_len int) bool {
	if nick == '' || nick.len > max_len || nick[0].is_digit() || nick[0] == `-` {
		return false
	}
	for c in nick {
		if !(c.is_letter() || c.is_digit() || c in [`-`, `_`, `[`, `]`, `\\`, `^`, `{`, `}`, `|`,
			`\``]) {
			return false
		}
	}
	return true
}

fn skip_spaces(s string) string {
	mut i := 0
	for i < s.len && s[i] == ` ` {
		i++
	}
	return s[i..]
}

// parse_tags parses the tag section of a line, without its leading `@`.
// When a key appears several times, the last value wins, as the specification
// requires. Tags with an invalid key are dropped.
pub fn parse_tags(raw string) ![]Tag {
	mut tags := []Tag{}
	if raw == '' {
		return parse_error('empty tag section')
	}
	for part in raw.split(';') {
		if part == '' {
			// A trailing or doubled `;` is tolerated.
			continue
		}
		eq := part.index_u8(`=`)
		key := if eq < 0 { part } else { part[..eq] }
		if !valid_tag_key(key) {
			// Receivers must not reject a message for a tag they cannot read
			// (message-tags specification); the tag is dropped.
			continue
		}
		value := if eq < 0 { '' } else { unescape_tag_value(part[eq + 1..]) }
		for i, t in tags {
			if t.key == key {
				tags.delete(i)
				break
			}
		}
		tags << Tag{
			key:   key
			value: value
		}
	}
	return tags
}

// valid_tag_key reports whether `key` is a valid tag key: an optional `+`, an
// optional vendor (a host name followed by `/`), then letters, digits and `-`.
pub fn valid_tag_key(key string) bool {
	mut k := key
	if k.starts_with('+') {
		k = k[1..]
	}
	slash := k.last_index_u8(`/`)
	if slash >= 0 {
		vendor := k[..slash]
		if vendor == '' {
			return false
		}
		for c in vendor {
			if !c.is_letter() && !c.is_digit() && c != `-` && c != `.` {
				return false
			}
		}
		k = k[slash + 1..]
	}
	if k == '' {
		return false
	}
	for c in k {
		if !c.is_letter() && !c.is_digit() && c != `-` {
			return false
		}
	}
	return true
}

// unescape_tag_value decodes a tag value: `\:` is `;`, `\s` a space, `\\` a
// backslash, `\r` and `\n` CR and LF. Other escaped characters stand for
// themselves and a trailing lone backslash is dropped.
pub fn unescape_tag_value(value string) string {
	if value.index_u8(`\\`) < 0 {
		return value
	}
	mut out := []u8{cap: value.len}
	mut i := 0
	for i < value.len {
		c := value[i]
		if c != `\\` {
			out << c
			i++
			continue
		}
		if i + 1 >= value.len {
			break
		}
		next := value[i + 1]
		out << match next {
			`:` { u8(`;`) }
			`s` { u8(` `) }
			`r` { u8(`\r`) }
			`n` { u8(`\n`) }
			else { next }
		}
		i += 2
	}
	return out.bytestr()
}

// escape_tag_value encodes a tag value for the wire. NUL bytes are dropped.
pub fn escape_tag_value(value string) string {
	mut out := []u8{cap: value.len}
	for c in value {
		match c {
			`;` { out << [u8(`\\`), `:`] }
			` ` { out << [u8(`\\`), `s`] }
			`\\` { out << [u8(`\\`), `\\`] }
			`\r` { out << [u8(`\\`), `r`] }
			`\n` { out << [u8(`\\`), `n`] }
			0 {}
			else { out << c }
		}
	}
	return out.bytestr()
}

// tag returns the value of the tag `key`, or none when the message has no such tag.
pub fn (m &Message) tag(key string) ?string {
	for t in m.tags {
		if t.key == key {
			return t.value
		}
	}
	return none
}

// has_tag reports whether the message has the tag `key`.
pub fn (m &Message) has_tag(key string) bool {
	return m.tag(key) != none
}

// param returns the parameter at `index`, or an empty string when there is none.
pub fn (m &Message) param(index int) string {
	return if index >= 0 && index < m.params.len { m.params[index] } else { '' }
}

// encode_tags returns tags as written after the `@` of a line (`a=1;b`), or an
// empty string when there are none. Tags with an invalid key are left out, so
// that the result is always well-formed.
pub fn encode_tags(tags []Tag) string {
	mut parts := []string{cap: tags.len}
	for t in tags {
		if !valid_tag_key(t.key) {
			continue
		}
		parts << if t.value == '' { t.key } else { '${t.key}=${escape_tag_value(t.value)}' }
	}
	return parts.join(';')
}

// str serializes the message, without CR LF. The last parameter is written
// as a trailing one when it is empty, contains a space or starts with `:`;
// other parameters that would need it are replaced with `*`.
// CR, LF and NUL are removed from the source, command and parameters so that
// the result is always a single line.
pub fn (m &Message) str() string {
	mut sb := []u8{cap: 128}
	tags := encode_tags(m.tags)
	if tags != '' {
		sb << `@`
		sb << tags.bytes()
		sb << ` `
	}
	if m.source != '' {
		sb << `:`
		sb << strip_line_breaks(m.source).bytes()
		sb << ` `
	}
	sb << strip_line_breaks(m.command).bytes()
	for i, p in m.params {
		mut param := strip_line_breaks(p)
		sb << ` `
		if i == m.params.len - 1 {
			if param == '' || param.contains(' ') || param.starts_with(':') {
				sb << `:`
			}
		} else if param == '' || param.contains(' ') || param.starts_with(':') {
			// A middle parameter cannot hold these: `*` keeps the parameter count.
			param = '*'
		}
		sb << param.bytes()
	}
	return sb.bytestr()
}

fn strip_line_breaks(s string) string {
	if !s.contains_any('\r\n\x00') {
		return s
	}
	return s.bytes().filter(it !in [`\r`, `\n`, 0]).bytestr()
}

// split_tags returns the length of the tag section of `line` (the `@` and
// the spaces after it included) and the length of the rest, so that callers
// can apply `max_client_tags_bytes` and `max_line_bytes` separately.
pub fn split_tags(line string) (int, int) {
	if !line.starts_with('@') {
		return 0, line.len
	}
	mut end := line.index_u8(` `)
	if end < 0 {
		return line.len, 0
	}
	for end < line.len && line[end] == ` ` {
		end++
	}
	return end, line.len - end
}
