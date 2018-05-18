#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>
#include "fsmtrie.h"

static void asearch_report_trial1(const char *str, int dist, void *data)
{
	const char *search_term = (const char *)data;

	ck_assert_str_eq(search_term, "tarsightsecuritz");
	ck_assert_int_eq(dist, 2);
	ck_assert_str_eq(str, "farsightsecurity");
}

static void asearch_report_trial2(const char *str, int dist, void *data)
{
	const char *search_term = (const char *)data;

	ck_assert_str_eq(search_term, "foobar");
	ck_assert_int_eq(dist, 2);
	ck_assert_str_eq(str, "foo");
}

static void subsearch_report_trial1(const char *str, int off, void *data)
{
	const char *search_term = (const char *)data;

	ck_assert_str_eq(search_term, "love");
	ck_assert_int_eq(off, 0);
	ck_assert_str_eq(str, "love");
}

static void subsearch_report_trial2(const char *str, int off, void *data)
{
	const char *search_term = (const char *)data;

	ck_assert_str_eq(search_term, "farsightsecurity");
	if (!strcmp(str, "sigh"))
	{
		ck_assert_int_eq(off, 3);
	}
	else if (!strcmp(str, "farsightsecurity"))
	{
		ck_assert_int_eq(off, 0);
	}
	else
	{
		ck_abort_msg("unknown str: %s\n", str);
	}
}

START_TEST(test_trie_insert_and_asearch_subsearch)
{
	int n;
	const char *str;
	fsmtrie_t fsmtrie;
	fsmtrie_opt_t opt;
	char err_buf[BUFSIZ];
	const char *keys[] = {
		"foo",
		"bar",
		"brad",
		"brady",
		"foobarbaz",
		"farsightsecurity",
		"sigh",
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

	ck_assert_int_eq(fsmtrie_search_approx(fsmtrie, "tarsightsecuritz", 2,
		asearch_report_trial1, "tarsightsecuritz"), 1);
	ck_assert_int_eq(fsmtrie_search_approx(fsmtrie, "foobar", 2,
		asearch_report_trial2, "foo"), 1);

	ck_assert_int_eq(fsmtrie_search_substring(fsmtrie, "love",
		subsearch_report_trial1, "love"), 1);
	ck_assert_int_eq(fsmtrie_search_substring(fsmtrie, "farsightsecurity",
		subsearch_report_trial2, "farsightsecurity"), 1);

	fsmtrie_opt_destroy(&opt);
	fsmtrie_destroy(&fsmtrie);
}
END_TEST

int main(void)
{
	int number_failed;
	Suite *s;
	TCase *tc_core;
	SRunner *sr;

	s = suite_create("fsmtrie_trie");
	tc_core = tcase_create("core");
	tcase_add_test(tc_core, test_trie_insert_and_asearch_subsearch);
	suite_add_tcase(s, tc_core);

	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
