# Copyright (c) 2015-2017 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
TESTS =
check_PROGRAMS =
noinst_PROGRAMS =
AM_CFLAGS        = $(my_CFLAGS)
AM_CPPFLAGS      = -I$(top_srcdir)/fsmtrie -I$(top_builddir)/fsmtrie
AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS  = -I m4 ${ACLOCAL_FLAGS}
AM_TESTS_ENVIRONMENT = top_builddir='$(top_builddir)'; \
		       top_srcdir='$(top_srcdir)'; \
		       export top_builddir top_srcdir;
TESTS_ENVIRONMENT = $(AM_TESTS_ENVIRONMENT)
AM_LDFLAGS =

USE_LCOV=@USE_LCOV@
LCOV=@LCOV@
GENHTML=@GENHTML@

clean-coverage:
	@if [ $(USE_LCOV) = yes ] ; then \
		$(LCOV) --directory . --zerocounters ; \
		echo "Removing coverage info files and generated $(abs_top_builddir)/coverage-html/ directory" ; \
		rm -rf all.coverage report.coverage ; \
		rm -rf $(abs_top_builddir)/coverage-html/ ; \
	else \
		echo "Code coverage not enabled at configuration time." ; \
		echo "Use: ./configure --with-coverage" ; \
fi

report-coverage:
	@if [ $(USE_LCOV) = yes ] ; then \
		$(LCOV) --capture --directory . --output-file all.coverage ; \
		$(LCOV) --remove all.coverage \
			$(abs_top_srcdir)/t/\* \
			/usr/include/\* \
			--output report.coverage ; \
		$(GENHTML) --legend -o $(abs_top_builddir)/coverage-html report.coverage ; \
		echo "Generated Code Coverage report in HTML at $(abs_top_builddir)/coverage-html" ; \
	else \
		echo "Code coverage not enabled at configuration time." ; \
		echo "Use: ./configure --with-coverage" ; \
fi

EXTRA_DIST       = COPYRIGHT
EXTRA_DIST       += README.md
EXTRA_DIST 	 += doc/doxygen/doxygen-input-filter

pkgconfig_DATA = ${LIBFSMTRIE_PC}
EXTRA_DIST += fsmtrie/libfsmtrie.pc.in

fsmtrieincludedir = $(includedir)
nobase_include_HEADERS = fsmtrie/fsmtrie.h fsmtrie/version.h
fsmtrieinclude_HEADERS 	 =

lib_LTLIBRARIES			  = fsmtrie/libfsmtrie.la
fsmtrie_libfsmtrie_la_CFLAGS     	  = $(AM_CFLAGS)
fsmtrie_libfsmtrie_la_SOURCES    	  = fsmtrie/fsmtrie.c \
				    fsmtrie/asearch.c \
				    fsmtrie/subsearch.c \
				    fsmtrie/private.c \
				    fsmtrie/version.c \
				    fsmtrie/version.h \
				    fsmtrie/fsmtrie.h \
				    fsmtrie/private.h
fsmtrie_libfsmtrie_la_LIBADD          = ${strlcpy_LIBS}
#
# Note: fsmtrie version 1.0.0 coincidentally had library version 1:0:0,
# but these two version numbers do not normally line up. The library
# versioning scheme used by libtool is documented at:
#
#    https://www.gnu.org/software/libtool/manual/libtool.html#Versioning
#
fsmtrie_libfsmtrie_la_LDFLAGS         = -version-info 3:0:0

# Documentation
if HAVE_DOXYGEN
html-local: doc/doxygen/Doxyfile
	$(AM_V_GEN) cd doc/doxygen && $(DOXYGEN)
endif

doc: html-local

clean-local:
	rm -rf doc/doxygen/html
	rm -rf doc/doxygen/latex
	rm -f doc/doxygen/doxygen.warnings

spotless: distclean
	rm -fr ar-lib aclocal.m4 autom4te.cache configure config.* Makefile.in \
        autoscan.log fsmtrie/config.h compile depcomp configure.scan       \
        doc/doxygen/Doxyfile missing install-sh ltmain.sh

noinst_PROGRAMS += \
		   examples/ascii \
		   examples/eascii \
		   examples/token \
		   examples/print_version

# Tests
TESTS += tests/test-trie-insert-and-search
check_PROGRAMS += tests/test-trie-insert-and-search
tests_test_trie_insert_and_search_SOURCES = tests/test-trie-insert-and-search.c
tests_test_trie_insert_and_search_LDADD = fsmtrie/libfsmtrie.la ${strlcpy_LIBS} \
					${check_LIBS}
tests_test_trie_insert_and_search_CFLAGS = ${AM_CFLAGS} ${check_CFLAGS} \
					 ${strlcpy_CFLAGS}

TESTS += tests/test-trie-insert-and-asearch-subsearch
check_PROGRAMS += tests/test-trie-insert-and-asearch-subsearch
tests_test_trie_insert_and_asearch_subsearch_SOURCES = \
	tests/test-trie-insert-and-asearch-subsearch.c
tests_test_trie_insert_and_asearch_subsearch_LDADD = fsmtrie/libfsmtrie.la \
						     ${strlcpy_LIBS} \
						     ${check_LIBS}
tests_test_trie_insert_and_asearch_subsearch_CFLAGS = ${AM_CFLAGS} \
						      ${check_CFLAGS} \
						      ${strlcpy_CFLAGS}

# Examples
examples_ascii_LDADD = fsmtrie/libfsmtrie.la
examples_ascii_SOURCES = examples/ascii.c
examples_eascii_LDADD = fsmtrie/libfsmtrie.la
examples_eascii_SOURCES = examples/eascii.c
examples_token_LDADD = fsmtrie/libfsmtrie.la
examples_token_SOURCES = examples/token.c
examples_print_version_LDADD = fsmtrie/libfsmtrie.la
examples_print_version_SOURCES = examples/print_version.c

TESTS += tests/run_examples_tests.sh
DISTCLEANFILES = tests/examples.eascii.out tests/examples.token.out \
		  tests/examples.ascii.out
EXTRA_DIST += tests/examples.ascii.cmp tests/examples.eascii.cmp \
		tests/examples.token.cmp
