## Farsight fsmtrie
This is the Fast String Matcher Trie project. This C-based library provides a
simple API for the storage and fast matching of ASCII, Extended ASCII, and
32-bit wide "token" strings.

It was originally inspired from code found [here](http://www.geeksforgeeks.org/trie-insert-and-search/).

### Building and installing fsmtrie
`fsmtrie` requires a C99 compiler and the `pkg-config` utility to be installed.
It may also depend on [libbsd](http://libbsd.freedesktop.org/wiki/)
(which should already be installed on BSD systems).
It has the following optional dependencies:

 * [doxygen](http://www.stack.nl/~dimitri/doxygen/) (be sure to use >= 1.8.3 that supports inlining markdown files)
 * [check](http://check.sourceforge.net/doc/check_html/) (be sure to use >= 0.10.0)

If building from a distribution tarball, the following command should build
and install `fsmtrie`:

`./configure && make && make install`

On platforms where the `pkg-config` utility is unavailable, `.pc` file
installation can be disabled by passing `--without-pkgconfigdir` to
`configure`.

If building from a git checkout, the `autotools` (`autoconf`, `automake`,
`libtool`) must also be installed, and the build system must be bootstrapped by
running the `autogen.sh` script:

`./autogen.sh && ./configure && make && make install`

To build the API documentation, you'll need doxygen installed and you should:

`make doc`

If you installed the `check` library, you can run the unit tests via:

`make check`

### API
The auto-generated doxygen-based manual has a complete API reference.

### Examples
The examples directory contains a handful of examples of how to use the fsmtrie
library.
