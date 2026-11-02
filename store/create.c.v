module store

import os

#include <fcntl.h>
#include <errno.h>

fn C.open(path &char, flags int, mode int) int
fn C.close(fd int) int

// create_private creates `path` with mode 600 if it does not exist yet. An
// existing file is left untouched.
fn create_private(path string) ! {
	fd := C.open(&char(path.str), C.O_CREAT | C.O_EXCL | C.O_WRONLY, 0o600)
	if fd >= 0 {
		C.close(fd)
		return
	}
	if C.errno != C.EEXIST {
		return error('cannot create ${path}: ${os.posix_get_error_msg(C.errno)}')
	}
}
