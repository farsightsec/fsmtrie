AC_PREREQ([2.64])

m4_define(fsmtrie_major_version, 2)
m4_define(fsmtrie_minor_version, 0)
m4_define(fsmtrie_patchlevel_version, 0)
m4_define(fsmtrie_version,
          fsmtrie_major_version.fsmtrie_minor_version.fsmtrie_patchlevel_version)
m4_define(fsmtrie_version_number,
	  m4_eval(fsmtrie_major_version * 1000000 + fsmtrie_minor_version * 1000 + fsmtrie_patchlevel_version))

AC_INIT([fsmtrie],
	[fsmtrie_version()],
	[https://github.com/farsightsec/fsmtrie/issues],
	[fsmtrie],
	[https://github.com/farsightsec/fsmtrie])
AC_CONFIG_SRCDIR([fsmtrie/fsmtrie.c])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules \
		  subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

FSMTRIE_MAJOR_VERSION=fsmtrie_major_version()
FSMTRIE_MINOR_VERSION=fsmtrie_minor_version()
FSMTRIE_PATCHLEVEL_VERSION=fsmtrie_patchlevel_version()
FSMTRIE_VERSION=fsmtrie_version()
FSMTRIE_VERSION_NUMBER=fsmtrie_version_number()

AC_SUBST(FSMTRIE_MAJOR_VERSION)
AC_SUBST(FSMTRIE_MINOR_VERSION)
AC_SUBST(FSMTRIE_PATCHLEVEL_VERSION)
AC_SUBST(FSMTRIE_VERSION)
AC_SUBST(FSMTRIE_VERSION_NUMBER)

AC_PROG_LN_S

AC_CONFIG_FILES([Makefile doc/doxygen/Doxyfile fsmtrie/libfsmtrie.pc fsmtrie/version.h])
AC_CONFIG_HEADER([config.h])

my_PKG_CONFIG_FILES([LIBFSMTRIE_PC], [fsmtrie/libfsmtrie.pc])

my_CFLAGS="-Wall \
	-Wmissing-declarations -Wmissing-prototypes \
	-Wnested-externs -Wpointer-arith \
	-Wpointer-arith -Wsign-compare -Wchar-subscripts \
	-Wstrict-prototypes -Wshadow \
	-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_PATH_PROG([DOXYGEN], [doxygen])
AM_CONDITIONAL([HAVE_DOXYGEN], [test -n "$DOXYGEN"])
if test -n "$DOXYGEN"; then
    DOC_HTML_MSG="yes, doxygen available: $DOXYGEN"
else
    DOC_HTML_MSG="no, doxygen not available"
fi

AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

PKG_CHECK_MODULES([check], [check >= 0.9.10],
		  [CHECK_MOD_MSG="yes"], [CHECK_MOD_MSG="no"])

AC_SEARCH_LIBS([strlcpy],
               [bsd],
               [strlcpy_LIBS="$LIBS"],
               [AC_MSG_ERROR([could not find libbsd, it can be downloaded here: http://libbsd.freedesktop.org/wiki/])]
              )
LIBS="$save_LIBS"
AC_SUBST(strlcpy_LIBS)

AC_CONFIG_FILES([tests/run_examples_tests.sh],
                [chmod +x tests/run_examples_tests.sh])

AC_ARG_WITH(coverage,
[  --with-coverage[=PROGRAM]  enable test coverage target using the specified lcov], lcov="$withval", lcov="no")

USE_LCOV="no"
if test "$lcov" != "no"; then
	if test "$lcov" != "yes"; then
		LCOV=$lcov
	else
		AC_PATH_PROG([LCOV], [lcov])
	fi
	if test -x "${LCOV}"; then
		USE_LCOV="yes"
	else
		AC_MSG_ERROR([Cannot find lcov.])
	fi
	# is genhtml always in the same directory?
	GENHTML=`echo "$LCOV" | ${SED} s/lcov$/genhtml/`
	if test ! -x $GENHTML; then
		AC_MSG_ERROR([genhtml not found, needed for lcov])
	fi
	CFLAGS="$CFLAGS --coverage"
	LIBS=" $LIBS -lgcov"
	AC_SUBST(LIBS)
	AC_SUBST(LCOV)
	AC_SUBST(GENHTML)
fi
AC_SUBST(USE_LCOV)

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:                   ${CC}
        cflags:                     ${CFLAGS}
        ldflags:                    ${LDFLAGS}
        libs:                       ${LIBS}

        prefix:                     ${prefix}
        sysconfdir:                 ${sysconfdir}
        libdir:                     ${libdir}
        includedir:                 ${includedir}

        building html docs:         ${DOC_HTML_MSG}
        make check available:       ${CHECK_MOD_MSG}
        code coverage enabled:      ${USE_LCOV}
])
