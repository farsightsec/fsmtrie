/*
 * Fast String Matcher Library EASCII Example
 *
 *  Copyright (c) 2015-2017 by Farsight Security, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fsmtrie/fsmtrie.h>

static void approx_print(const char *str, int dist, void *data)
{
	const char *search_term = (const char *)data;
	printf("%s: %s (distance=%d)\n", search_term, str, dist);
}

static void substring_print(const char *str, int off, void *data)
{
	const char *search_term = (const char *)data;
	printf("%s: %s (offset=%d)\n", search_term, str, off);
}

int main(int argc, char **argv)
{
	int n;
	const char *keys[] = {
		"\u03DC\u0251\u16B1\u054F\u13A5\u050C\u13BB\u13A2",
		"\uFF37\u13A5\uFF2E\u13E6",
		"\u16B1\uFF35\u16D6\u2160",
		"\u0455\u13A5\u050C\u041D",
		0
	};

	const char *search[] = {
		"\u03DC\u0251\u16B1\u054F\u13A5\u050C\u13BB\u13A2",
		"\uFF37\u13A5\uFF2E\u13E6",
		"\u16B1\uFF35\u16D6\u2160",
		"\u03DC\u0251\u16B1",
		"\uFF37\u13A5\uFF2E",
		"\u16B1\uFF35\u16D6",
		"\u03DCA\u16B1\u054F\u13A5\u050C\u13BB\u13A2",
		"\u054F\u13A5\u050C\u13BB",
		"\u03DC\u00C3\u16B1\u0455\u13A5\u050C\u041Dt\u10BD\u00CB\u13DF\u0531\u053B\u13A5\u0422\u04AE",
		0
	};

	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	const char *str;
	char err_buf[BUFSIZ];

	printf("Initializing new EASCII fsmtrie options object\n");
	opt = fsmtrie_opt_init();
	if (opt == NULL)
	{
		fprintf(stderr, "can't initialize fsmtrie options object\n");
		return (EXIT_FAILURE);
	}

	if (!fsmtrie_opt_set_mode(opt, fsmtrie_mode_eascii))
	{
		fprintf(stderr, "can't set mode\n");
		fsmtrie_opt_destroy(&opt);
		return (EXIT_FAILURE);
	}
	if (!fsmtrie_opt_set_maxlength(opt, 64))
	{
		fprintf(stderr, "can't set max length\n");
		fsmtrie_opt_destroy(&opt);
		return (EXIT_FAILURE);
	}
	if (!fsmtrie_opt_set_partialmatch(opt, true))
	{
		fprintf(stderr, "can't set partial match flag\n");
		fsmtrie_opt_destroy(&opt);
		return (EXIT_FAILURE);
	}

	printf("Initializing new EASCII fsmtrie\n");
	fsmtrie = fsmtrie_init(opt, err_buf);
	if (fsmtrie == NULL)
	{
		fprintf(stderr, "%s\n", err_buf);
		fsmtrie_opt_destroy(&opt);
		return (EXIT_FAILURE);
	}

	printf("Inserting keys...\n");
	for (n = 0; keys[n]; n++)
	{
		if (!fsmtrie_insert(fsmtrie, keys[n], keys[n]))
		{
			fprintf(stderr, "failed to insert key \"%s\": %s\n",
					keys[n],
					fsmtrie_error(fsmtrie));
			fsmtrie_destroy(&fsmtrie);
			fsmtrie_opt_destroy(&opt);
			return (EXIT_FAILURE);
		}
	}
	printf("Done, inserted %d keys\n", n);

	printf("fsmtrie contains %u nodes", fsmtrie_get_nodecnt(fsmtrie));
	printf(" and the following %d leaves:\n", n);
	fsmtrie_print_leaves(fsmtrie);

	printf("\nExample 1: look for original keys\n");
	for (n = 0; keys[n]; n++)
	{
		switch (fsmtrie_search(fsmtrie, keys[n], &str))
		{
			case 0:
				fprintf(stderr, "failed to find key %s\n",
						keys[n]);
				break;
			case 1:
				printf("found %s (leaf = %s)\n", keys[n], str);
				break;
			case -1:
				fprintf(stderr, "%s\n",
						fsmtrie_get_error(fsmtrie));
				break;
			default:
				break;
		}
	}

	printf("\nExample 2: look for search terms\n");
	for (n = 0; search[n]; n++)
	{
		switch (fsmtrie_search(fsmtrie, search[n], &str))
		{
			case 0:
				fprintf(stderr, "failed to find key %s\n",
						search[n]);
				break;
			case 1:
				printf("found %s (leaf = %s)\n", search[n],
						str);
				break;
			case -1:
				fprintf(stderr, "%s\n",
						fsmtrie_get_error(fsmtrie));
				break;
			default:
				break;
		}
	}

	printf("\nExample 3: look for search terms with partial matches\n");
	for (n = 0; search[n]; n++)
	{
		switch (fsmtrie_search(fsmtrie, search[n], &str))
		{
			case 0:
				fprintf(stderr, "failed to find key %s\n",
						search[n]);
				break;
			case 1:
				printf("found %s (leaf = %s)\n", search[n],
						str);
				break;
			case -1:
				fprintf(stderr, "%s\n",
						fsmtrie_get_error(fsmtrie));
				break;
			default:
				break;
		}
	}

	printf("\nExample 4: look for search terms with approximate matches"
			" (distance of 2)\n");
	for (n = 0; search[n]; n++)
	{
		printf("looking for %s...\n", search[n]);
		switch (fsmtrie_search_approx(fsmtrie, search[n], 2,
					approx_print, (void *)search[n]))
		{
			case -1:
				fprintf(stderr, "%s\n",
						fsmtrie_get_error(fsmtrie));
				break;
			case 1:
			default:
				break;
		}
	}

	printf("\nExample 5: look for search terms with substring matches\n");
	for (n = 0; search[n]; n++)
	{
		printf("looking for %s...\n", search[n]);
		switch (fsmtrie_search_substring(fsmtrie, search[n],
					substring_print, (void *)search[n]))
		{
			case -1:
				fprintf(stderr, "%s\n",
						fsmtrie_get_error(fsmtrie));
				break;
			case 1:
			default:
				break;
		}
	}

	fsmtrie_destroy(&fsmtrie);
	fsmtrie_opt_destroy(&opt);

	return (EXIT_SUCCESS);
}
