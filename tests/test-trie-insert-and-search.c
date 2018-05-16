#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>
#include "fsmtrie.h"

START_TEST(test_trie_insert_and_search)
{
	int n;
	const char *str;
	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	char err_buf[BUFSIZ];
	const char *keys[] = {
		"foo",
		"bar",
		"baz",
		"brad",
		"brady",
		"foobarbaz",
		"farsightsecurity",
		"fsi",
		"fsizn",
		"love",
		"hate",
		"dogs",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		0 };

	ck_assert_ptr_ne(opt = fsmtrie_opt_init(), NULL);
	ck_assert_int_eq(fsmtrie_opt_set_mode(opt, fsmtrie_mode_ascii), 1);
	ck_assert_int_eq(fsmtrie_opt_set_maxlength(opt, 64), 1);
	ck_assert_int_eq(fsmtrie_opt_set_partialmatch(opt, true), 1);
	ck_assert_ptr_ne(fsmtrie = fsmtrie_init(opt, err_buf), NULL);

	for (n = 0; keys[n]; n++)
	{
		ck_assert_int_eq(fsmtrie_insert(fsmtrie, keys[n], keys[n]), 1);
	}
	for (n = 0; keys[n]; n++)
	{
		ck_assert_int_eq(fsmtrie_search(fsmtrie, keys[n], &str), 1);
		ck_assert_str_eq(str, keys[n]);
	}
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "FAIL-1", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "FAIL-2", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "FAIL-3", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "cats", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "bradyy", &str), 0);

	/* test partial match mode */
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "lov", &str), 1);
	ck_assert_ptr_eq(str, NULL);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "hat", &str), 1);
	ck_assert_ptr_eq(str, NULL);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "foob", &str), 1);
	ck_assert_ptr_eq(str, NULL);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "farsightsecurit", &str), 1);
	ck_assert_ptr_eq(str, NULL);

	fsmtrie_opt_free(opt);
	fsmtrie_destroy(&fsmtrie);
}
END_TEST

START_TEST(test_trie_insert_and_search_token)
{
	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	char err_buf[BUFSIZ];
	const char *str;
	int n;
	uint32_t tokens[10][10] = {
		{ 2370247590, 1095180747, 74714336, 3949875523, 1491746051,
			3884494044, 225220230, 4025198788, 2517868197,
			880604605 },
		{ 95487574, 1409786191, 193961985, 3871872763, 167319551,
			3652317314, 3835276744, 2979764266, 2736512810,
			595523817 },
		{ 1111211003, 1238082513, 3063407297, 2604351, 209841200,
			583699085, 1198663276, 576252664, 2278303155,
			3116239803 },
		{ 4014953343, 3195325339, 3220670815, 146706452, 1622571885,
			1209586832, 262755701, 1359575583, 3266543654,
			3374402931 },
		{ 1081959495, 1314696305, 74120600, 4143224036, 212177622,
			3831015299, 2332140422, 230234173, 1817729371,
			2397671606 },
		{ 1653555818, 431545239, 400999384, 1748239015, 373402022,
			1829571174, 2684328923, 368298069, 3812059388,
			939495951 },
		{ 1633698524, 3469601330, 1754464514, 66377614, 465588532,
			3955372159, 2488742623, 302013022, 1000627217,
			1368687343 },
		{ 4056458840, 2021502446, 70785067, 3343881455, 1533111212,
			2048810699, 1609199684, 1291371295, 325355373,
			2766376604 },
		{ 225858940, 3215793256, 2105674179, 166917351, 1730990860,
			2891934650, 3374477436, 2151851239, 201682630,
			1463624149 },
		{ 70000920, 3140941181, 4132200293, 630768445, 195394958,
			3794809138, 1638949419, 1839633380, 478263424,
			53519825 }
	};
	char *toknames[10] = { "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8",
		"t9", "t10" };

	ck_assert_ptr_ne(opt = fsmtrie_opt_init(), NULL);
	ck_assert_int_eq(fsmtrie_opt_set_mode(opt, fsmtrie_mode_token), 1);
	ck_assert_int_eq(fsmtrie_opt_set_maxlength(opt, 10), 1);
	ck_assert_ptr_ne(fsmtrie = fsmtrie_init(opt, err_buf), NULL);

	for (n = 0; n < 10; n++)
	{
		ck_assert_int_eq(fsmtrie_insert_token(fsmtrie, tokens[n], 10,
					toknames[n]), 1);
	}

	for (n = 0; n < 10; n++)
	{
		ck_assert_int_eq(fsmtrie_search_token(fsmtrie, tokens[n], 10,
					&str), 1);
		ck_assert_str_eq(str, toknames[n]);
	}

	for (n = 0; n < 10; n++)
	{
		tokens[n][0]++;
	}

	for (n = 0; n < 10; n++)
	{
		ck_assert_int_eq(fsmtrie_search_token(fsmtrie, tokens[n], 10,
					&str), 0);
	}

	fsmtrie_opt_free(opt);
	fsmtrie_destroy(&fsmtrie);
}
END_TEST

START_TEST(test_trie_insert_and_search_ml)
{
	const char *str;
	uint32_t max_len;
	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	char err_buf[BUFSIZ];
	const char *keys[] = {
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		0 };

	ck_assert_ptr_ne(opt = fsmtrie_opt_init(), NULL);
	ck_assert_int_eq(fsmtrie_opt_set_mode(opt, fsmtrie_mode_ascii), 1);
	max_len = strlen(keys[0]);
	ck_assert_int_eq(fsmtrie_opt_set_maxlength(opt, max_len), 1);
	ck_assert_ptr_ne(fsmtrie = fsmtrie_init(opt, err_buf), NULL);

	/* fits */
	ck_assert_int_eq(fsmtrie_insert(fsmtrie, keys[0], keys[0]), 1);

	/* too big */
	ck_assert_int_eq(fsmtrie_insert(fsmtrie, keys[1], keys[1]), 0);
	ck_assert_int_eq(fsmtrie_insert(fsmtrie, keys[2], keys[2]), 0);
	ck_assert_int_eq(fsmtrie_insert(fsmtrie, keys[3], keys[3]), 0);

	ck_assert_int_eq(fsmtrie_search(fsmtrie, keys[0], &str), 1);
	ck_assert_str_eq(str, keys[0]);

	/* test partial match mode: should fail */
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "xxxxxxxxxx", &str), 0);

	fsmtrie_opt_free(opt);
	fsmtrie_destroy(&fsmtrie);
}
END_TEST


START_TEST(test_trie_insert_and_search_utf8)
{
	int n;
	const char *str;
	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	char err_buf[BUFSIZ];
	const char *keys[] = {
		"ϜɑᚱՏᎥԌᎻᎢ",
		"rԱϺᎥ",
		"ѡіΝᛕᏞĚＮ",
		0 };

	ck_assert_ptr_ne(opt = fsmtrie_opt_init(), NULL);
	ck_assert_int_eq(fsmtrie_opt_set_mode(opt, fsmtrie_mode_eascii), 1);
	ck_assert_int_eq(fsmtrie_opt_set_partialmatch(opt, true), 1);
	ck_assert_ptr_ne(fsmtrie = fsmtrie_init(opt, err_buf), NULL);

	for (n = 0; keys[n]; n++)
	{
		ck_assert_int_eq(fsmtrie_insert(fsmtrie, keys[n], keys[n]), 1);
	}
	for (n = 0; keys[n]; n++)
	{
		ck_assert_int_eq(fsmtrie_search(fsmtrie, keys[n], &str), 1);
		ck_assert_str_eq(str, keys[n]);
	}
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "FAIL-1", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "FAIL-2", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "FAIL-3", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "farsightsecurit", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "cats", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "bradyy", &str), 0);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "hat", &str), 0);

	/* test partial match mode */

	ck_assert_int_eq(fsmtrie_search(fsmtrie, "ϜɑᚱՏᎥ", &str), 1);
	ck_assert_ptr_eq(str, NULL);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "rԱϺ", &str), 1);
	ck_assert_ptr_eq(str, NULL);
	ck_assert_int_eq(fsmtrie_search(fsmtrie, "ѡіΝᛕ", &str), 1);
	ck_assert_ptr_eq(str, NULL);

	fsmtrie_opt_free(opt);
	fsmtrie_destroy(&fsmtrie);
}
END_TEST

int main(void) {
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("fsmtrie_trie");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_trie_insert_and_search);
	tcase_add_test(tc_core, test_trie_insert_and_search_ml);
	tcase_add_test(tc_core, test_trie_insert_and_search_utf8);
	tcase_add_test(tc_core, test_trie_insert_and_search_token);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
