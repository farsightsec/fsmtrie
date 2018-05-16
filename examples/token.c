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

#define KEY_CNT 4
#define KEY_LEN 5

int main(int argc, char **argv)
{
	int n;
	uint32_t keys[KEY_CNT][KEY_LEN] = {
		{123456789, 1234567890, 234567890, 3456789012, 456789012},
		{1000000000, 2000000000, 3000000000, 4000000000, 1},
		{0xdeadbeef, 0xdeadfeed, 0xc01055a1, 0xbabb1e, 0xf1eece},
		{0xdead, 0xfeed, 0xbeef, 0xf1ed, 0xf00f},
	};
	uint32_t search[KEY_CNT][KEY_LEN] = {
		{123456789, 1234567890, 234567890, 3456789012},
		{1000000000, 2000000000, 3000000000},
		{0xdeadbeef, 0xdeadfeed, 0xc01055a1, 0xbabb1e},
		{0xdead, 0xfeed, 0xbeef, 0xf1ed, 0xf00f},
	};
	const char *key_names[] = {
		"some numbers",
		"some other numbers",
		"there are also numbers",
		"once more friend, here are numbers",
	};
	const char *search_names[] = {
		"some numbers I'm looking for",
		"some other numbers I'm searching for",
		"there are also numbers I'd like to find",
		"once more friend, here are numbers I wish I could locate",
	};

	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	const char *str;
	char err_buf[BUFSIZ];

	printf("Initializing new fsmtrie options object\n");
	opt = fsmtrie_opt_init();
	if (opt == NULL)
	{
		fprintf(stderr, "can't initialize fsmtrie options object\n");
		return (EXIT_FAILURE);
	}

	if (!fsmtrie_opt_set_mode(opt, fsmtrie_mode_token))
	{
		fprintf(stderr, "can't set mode\n");
		fsmtrie_opt_free(opt);
		return (EXIT_FAILURE);
	}

	printf("Initializing new token fsmtrie\n");
	fsmtrie = fsmtrie_init(opt, err_buf);
	if (fsmtrie == NULL)
	{
		fprintf(stderr, "%s\n", err_buf);
		fsmtrie_opt_free(opt);
		return (EXIT_FAILURE);
	}

	printf("Inserting keys...\n");
	for (n = 0; n < KEY_CNT; n++)
	{
		if (!fsmtrie_insert_token(fsmtrie, keys[n], 5, key_names[n]))
		{
			fprintf(stderr, "failed to insert key \"%s\": %s\n",
					key_names[n],
					fsmtrie_error(fsmtrie));
			fsmtrie_destroy(&fsmtrie);
			fsmtrie_opt_free(opt);
			return (EXIT_FAILURE);
		}
	}
	printf("Done, inserted %d keys\n", n);

	printf("fsmtrie contains %u nodes", fsmtrie_get_nodecnt(fsmtrie));
	printf(" and the following %d leaves:\n", n);
	fsmtrie_print_leaves(fsmtrie);

	printf("\nExample 1: look for original keys\n");
	for (n = 0; n < KEY_CNT; n++)
	{
		switch (fsmtrie_search_token(fsmtrie, keys[n], 5, &str))
		{
			case 0:
				fprintf(stderr, "failed to find key %s\n",
						key_names[n]);
				break;
			case 1:
				printf("found %s (leaf = %s)\n",
						key_names[n], str);
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
	for (n = 0; n < KEY_CNT; n++)
	{
		switch (fsmtrie_search_token(fsmtrie, search[n], 5, &str))
		{
			case 0:
				fprintf(stderr, "failed to find key %s\n",
						search_names[n]);
				break;
			case 1:
				printf("found %s (leaf = %s)\n",
						search_names[n], str);
				break;
			case -1:
				fprintf(stderr, "%s\n",
						fsmtrie_get_error(fsmtrie));
				break;
			default:
				break;
		}
	}

	fsmtrie_destroy(&fsmtrie);
	fsmtrie_opt_free(opt);

	return (EXIT_SUCCESS);
}
