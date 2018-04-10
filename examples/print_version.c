#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#include <fsmtrie.h>

int
main(int argc, char **argv) {

/* to do compile-time checking, do something like the following: */
#if FSMTRIE_LIBRARY_VERSION_NUMBER >= 1000000
	printf("your install of libfsmtrie supports compile-time versioning ");
	printf("(FSMTRIE_LIBRARY_VERSION_NUMBER == %lu)\n",
			FSMTRIE_LIBRARY_VERSION_NUMBER);
#else
	printf("your install of libfsmtrie predates versioning, consider an upgrade\n");
	return (EXIT_SUCCESS);
#endif

	/* to do run-time checking, do something like the following: */
	printf("libfsmtrie run-time version is %d\n", fsmtrie_get_version_number());

	/* and to emit a stringified version number, do this: */
	printf("this program was linked against libfsmtrie version %s\n",
			fsmtrie_get_version());

	return (EXIT_SUCCESS);
}
