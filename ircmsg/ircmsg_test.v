module ircmsg

fn test_parse_full_line() {
	m := parse('@time=2026-11-02T00:00:00.000Z;+example.com/x=a\\sb\\:c :nick!u@h PRIVMSG #chan :hello world')!
	assert m.tags.len == 2
	assert m.tag('time')? == '2026-11-02T00:00:00.000Z'
	assert m.tag('+example.com/x')? == 'a b;c'
	assert m.source == 'nick!u@h'
	assert m.command == 'PRIVMSG'
	assert m.params == ['#chan', 'hello world']
}

fn test_parse_params() {
	assert parse('ping')!.command == 'PING'
	assert parse('USER u 0 * :Real Name')!.params == ['u', '0', '*', 'Real Name']
	assert parse('PRIVMSG  #a   :')!.params == ['#a', '']
	assert parse('NICK  a  ')!.params == ['a']
	assert parse('CMD :a:b c')!.params == ['a:b c']
	assert parse('CMD a:b')!.params == ['a:b']
}

fn test_parse_rejects() {
	for line in ['', ' ', '@a=b', ':src', '@a :b', 'PRIV\x00MSG x', 'A\rB', ': CMD'] {
		if _ := parse(line) {
			assert false, 'accepted ${line}'
		}
	}
	mut many := 'CMD'
	for _ in 0 .. 16 {
		many += ' p'
	}
	if _ := parse(many) {
		assert false
	}
}

fn test_tags_escaping() {
	assert unescape_tag_value('a\\\\b\\nc\\rd\\xe\\') == 'a\\b\nc\rdxe'
	for v in ['', 'plain', 'a b;c\\d\r\n', ';;  \\\\'] {
		assert unescape_tag_value(escape_tag_value(v)) == v
	}
	tags := parse_tags('a=1;b;a=2;c=')!
	assert tags.len == 3
	assert tags[1] == Tag{'a', '2'}
	assert tags[2] == Tag{'c', ''}
}

fn test_invalid_tag_keys_are_dropped() {
	m := parse('@=x;a_b=1;ok=2;+ PING')!
	assert m.tags == [Tag{'ok', '2'}]
	assert parse('001 nick :hi')!.command == '001'
	assert parse('nonexistent_command x')!.command == 'NONEXISTENT_COMMAND'
}

fn test_valid_nickname() {
	for nick in ['a', 'Nick_[x]', 'a-1', '`^{|}\\'] {
		assert valid_nickname(nick, 30), nick
	}
	for nick in ['', '1a', '-a', 'a b', 'a.b', 'é', 'abcd'] {
		assert !valid_nickname(nick, 3), nick
	}
}

fn test_tag_keys() {
	assert valid_tag_key('msgid')
	assert valid_tag_key('+draft/reply')
	assert valid_tag_key('+example.com/foo-bar')
	assert !valid_tag_key('')
	assert !valid_tag_key('+')
	assert !valid_tag_key('/a')
	assert !valid_tag_key('a_b')
	assert !valid_tag_key('ex/')
}

fn test_serialize() {
	m := Message{
		tags:    [Tag{'time', 'x'}, Tag{'+a', 'b c'}, Tag{'flag', ''}]
		source:  'srv'
		command: 'PRIVMSG'
		params:  ['#c', 'hi there']
	}
	assert m.str() == '@time=x;+a=b\\sc;flag :srv PRIVMSG #c :hi there'
	assert Message{
		command: 'X'
		params:  ['a', '']
	}.str() == 'X a :'
	assert Message{
		command: 'X'
		params:  [':a']
	}.str() == 'X ::a'
	assert Message{
		command: 'X'
		params:  ['a\r\nQ\x00UIT']
	}.str() == 'X aQUIT'
	assert Message{
		command: 'X'
		params:  ['a b', '', ':c', 'last one']
	}.str() == 'X * * * :last one'
	round := parse(m.str())!
	assert round.tags == m.tags
	assert round.params == m.params
}

fn test_split_tags() {
	a, b := split_tags('PING x')
	assert a == 0 && b == 6
	c, d := split_tags('@a=b  PING')
	assert c == 6 && d == 4
}

fn test_casemapping() {
	assert Casemapping.rfc1459.fold('Nick[]\\^') == 'nick{}|~'
	assert Casemapping.strict_rfc1459.fold('A^') == 'a^'
	assert Casemapping.ascii.fold('A[') == 'a['
}
