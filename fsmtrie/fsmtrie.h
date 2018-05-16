/*
 * Fast String Matcher Public Interface
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

#ifndef FSMTRIE_H
#define FSMTRIE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>
#ifdef __linux
#include <bsd/string.h>
#endif

#include <fsmtrie/version.h>

/**
 *  @file fsmtrie.h
 *  @brief libfsmtrie public interface
 */

/** fsmtrie modes of operation */
enum fsmtrie_mode
{
	fsmtrie_mode_ascii,		/**< 7-bit ASCII */
	fsmtrie_mode_eascii,		/**< extended "full-byte" ASCII */
	fsmtrie_mode_token,		/**< 32-bit wide token */
};

/* \cond */
typedef enum fsmtrie_mode fsmtrie_mode;
typedef struct fsmtrie * fsmtrie_t;
typedef struct fsmtrie_opt * fsmtrie_opt_t;
/* \endcond */

/**
 *  \defgroup fsmtrie fsmtrie
 *
 *  `fsmtrie` is a trie-based C library containing an API to build a system for
 *  the storage and efficient retrieval of different types of data.
 *
 *  The library supports three different modes of operation: ASCII, extended
 *  ASCII, and token.
 *
 *  The ASCII mode is intended for the storage and retrieval of 7-bit ASCII
 *  strings. The extended ASCII mode is intended for "full byte" strings
 *  suitable for storage and retrieval of Unicode encoded codepoints. The
 *  token mode is intended for the storage and retrieval of 32-bit wide token
 *  "strings".
 *
 *  At its core, the `fsmtrie` library builds a simple non-space optimized
 *  trie that can store an arbitrary number of keys of arbitrary maximum
 *  length.
 *
 *  For ASCII and extended ASCII fsmtries, insertion and lookup efficient with
 *  worst case running times of `O(M)` where M is the maximum key length.
 *
 *  For token fsmtries, each node will reference a variable number of child
 *  nodes that can grow dynamically as more content is subsequently added to
 *  the trie. Node children are located via binary search, so traversal will
 *  be slightly slower (`O(M * log(n))`) than for its traditional
 *  statically-sized fsmtrie counterpart.
 *
 *  ASCII and extended ASCII fsmtries support the concept of "partial
 *  matching" which allows truncated matches to return true (more on this
 *  below).
 *
 *  All modes support the clamping of key length with the "max length" option.
 *  If a key longer than this value is subsequently attempted to be inserted,
 *  an error is thrown (more on this below).
 *
 *  ASCII and extended ASCII data may be searched for in whole, in part, as
 *  sub-strings, or using a bounded edit-distance. Token data may be searched
 *  for in whole only. Specifics on search functions, including their running
 *  times, is below.
 *
 * @{
 */

/**
 *  Initialize a new fsmtrie. This function MUST be called before using any
 *  other fsmtrie function on the supplied fsmtrie. The caller MUST also
 *  check that this function returned non-NULL before using any other
 *  fsmtrie function.
 *
 *  If a NULL options object is supplied, default settings are used (\p
 *  fsmtrie_mode_ascii, no other options set).
 *
 *  Once an fsmtrie is initialized, keys may be inserted and searched for
 *  using appropriate functions as per the following table:
 *
 *  MODE|OPTIONS ALLOWED|INSERT FUNCTION|SEARCH FUNCTION(S)
 *  ----|-------------|---------------|---------------
 *  \p fsmtrie_mode_ascii|partial match, max length|fsmtrie_insert()|fsmtrie_search(), fsmtrie_search_approx(), fsmtrie_search_substring()
 *  \p fsmtrie_mode_eascii|partial match, max length|fsmtrie_insert()|fsmtrie_search(), fsmtrie_search_approx(), fsmtrie_search_substring()
 *  \p fsmtrie_mode_token|max length|fsmtrie_insert_token()|fsmtrie_search_token()
 *
 *  It is an error to use a different insert or search function other than
 *  what is listed above.
 *
 *  More than one fsmtrie may be concurrently initialized and used.
 *
 *  \param[in] opt pointer to a valid fsmtrie options object or NULL to use
 *  the default options
 *  \param[out] err_buf if something goes wrong, this will contain the reason
 *
 *  \returns a valid pointer to a new fsmtrie or NULL and err_buf will contain
 *  the reason
 */
fsmtrie_t fsmtrie_init(fsmtrie_opt_t opt, char *err_buf);

/**
 *  Initialize a new fsmtrie options object. This function MUST be called
 *  before using any other fsmtrie_opt* function on the supplied opt. The
 *  caller MUST also check that this function returned non-NULL before using
 *  any other fsmtrie_opt* function.
 *
 *  Note that no sanity checking is performed to ensure mode and options
 *  are congruent during the options setting process. Rather, this step
 *  is performed during fsmtrie initialization.
 *
 *  Also note that if a mode is not set, the default of `fsmtrie_mode_ascii`
 *  is used.
 *
 *  You can reuse options objects across multiple fsmtrie objects.
 *
 *  \returns a valid pointer to a new fsmtrie options object or NULL if
 *  memory allocation failed.
 */
fsmtrie_opt_t fsmtrie_opt_init(void);

/**
 *  Decommission a specified fsmtrie options object and free all memory
 *  associated with it.
 *
 *  \param[in] opt valid fsmtrie options object
 */
void fsmtrie_opt_free(fsmtrie_opt_t opt);

/**
 *  Set the fsmtrie mode.
 *
 *  \param[in] opt valid fsmtrie options object
 *  \param[in] mode an \p fsmtrie_mode
 *
 *  \retval true mode was set
 *  \retval false mode was not able to be set (opt was invalid)
 */
bool fsmtrie_opt_set_mode(fsmtrie_opt_t opt, fsmtrie_mode mode);

/**
 *  Get the fsmtrie mode.
 *
 *  \param[in] opt valid fsmtrie options object
 *  \param[in] mode will contain the mode
 *
 *  \retval true successful call, check mode
 *  \retval false failure, opt was invalid
 */
bool fsmtrie_opt_get_mode(fsmtrie_opt_t opt, fsmtrie_mode *mode);

/**
 *  Set the key max length. Enabling this option will cause fsmtrie to
 *  check and reject keys that are longer than `max_len`. Setting a `max_len`
 *  to `0` will disable length checking.
 *
 *  \param[in] opt valid fsmtrie options object
 *  \param[in] max_len size of the largest key allowed
 *
 *  \retval true option was set
 *  \retval false option was not able to be set (opt was invalid)
 */
bool fsmtrie_opt_set_maxlength(fsmtrie_opt_t opt, uint32_t max_len);

/**
 *  Get the key max length.
 *
 *  \param[in] opt valid fsmtrie options object
 *  \param[in] max_len will contain the max length
 *
 *  \retval true successful call, check max_len
 *  \retval false failure, opt was invalid
 */
bool fsmtrie_opt_get_maxlength(fsmtrie_opt_t opt, uint32_t *max_len);

/**
 *  Set the partial match flag. Enabling this option will cause fsmtrie to
 *  match search terms at an arbitrary number of characters starting at the 0th
 *  character of the inserted key. So if the key "doggies" was inserted and the
 *  partial match flag is set, searches for "doggie", "dogg", and "dog" will
 *  all return true (as will the search for "doggies"). When a match is partial
 *  the leaf node is not returned, so any inserted leaf node strings cannot be
 *  returned.
 *
 *  Note this option is only supported by ASCII and extended ASCII fsmtries.
 *
 *  \param[in] opt valid fsmtrie options object
 *  \param[in] on an \p fsmtrie_mode
 *
 *  \retval true option was set
 *  \retval false option was not able to be set (opt was invalid)
 */
bool fsmtrie_opt_set_partialmatch(fsmtrie_opt_t opt, bool on);

/**
 *  Get the partial match status.
 *
 *  \param[in] opt valid fsmtrie options object
 *  \param[in] on will be true if partial match is enabled
 *
 *  \retval true successful call, check on
 *  \retval false failure, opt was invalid
 */
bool fsmtrie_opt_get_partialmatch(fsmtrie_opt_t opt, bool *on);

/**
 *  Validate that a string contains only 7-bit ASCII characters and if
 *  `max_len` was set, is less than or equal to the `max_len` parameter
 *  specified at init time (this value can be culled via
 *  fsmtrie_opt_get_maxlength()).
 *
 *  For `fsmtrie_mode_eascii` or `fsmtrie_mode_token` fsmtries, this function
 *  is a no-op and always returns true.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 *  \param[in] key string to validate
 *
 *  \retval true key is valid
 *  \retval false key is invalid, call fsmtrie_get_error() the reason
 */
bool fsmtrie_key_validate_ascii(fsmtrie_t fsmtrie, const char *key);

/**
 *  Insert an ASCII or Extended ASCII key into a specified fsmtrie. Optionally,
 *  a string can be specified to copy to the leaf node; ostensibly this should
 *  be the key itself.
 *
 *  Valid for \p fsmtrie_mode_ascii and \p fsmtrie_mode_eascii fsmtries.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 *  \param[in] key string to add
 *  \param[in] str optional string to copy to leaf node
 *
 *  \retval true key was inserted
 *  \retval false key was not inserted, call fsmtrie_get_error() to get the
 *  reason
 */
bool fsmtrie_insert(fsmtrie_t fsmtrie, const char *key, const char *str);
/* \cond */
bool fsmtrie_insert_ascii(fsmtrie_t fsmtrie, const char *key,
		const char *str);
bool fsmtrie_insert_eascii(fsmtrie_t fsmtrie, const char *key,
		const char *str);
/* \endcond */


/**
 *  Insert a 32-bit wide token key into a specified fsmtrie.
 *
 *  Valid for \p fsmtrie_mode_token fsmtries.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 *  \param[in] tkey an array of 32-bit token values to be stored
 *  \param[in] nkey the number of elements in the token key array
 *  \param[in] str optional string to copy to leaf node
 *
 *  \retval true key was inserted
 *  \retval false key was not inserted, call fsmtrie_get_error() to get the
 *  reason
 */
bool fsmtrie_insert_token(fsmtrie_t fsmtrie, uint32_t *tkey, size_t nkey,
		const char *str);

/**
 *  Decommission a specified fsmtrie and free all memory associated with it.
 *
 *  Note that this function does not free the memory associated with fsmtrie,
 *  and free() should be called to avoid leaking that memory.
 *
 *  This function is deprecated in favor of fsmtrie_destroy().
 *
 *  \param[in] fsmtrie a valid fsmtrie object
 */
void fsmtrie_free(fsmtrie_t fsmtrie);


/**
 *  Destroy a specified fsmtrie, freeing all memory associated with it.
 *
 *  \param[in] fsmtrie pointer to a valid fsmtrie object
 */
void fsmtrie_destroy(fsmtrie_t *fsmtrie);


/**
 *  Search a specified fsmtrie for a key. If key is found, str may point to
 *  the string stored at insertion time. If \p FSMTRIE_PM_OK was set at
 *  initialization time, the function will return true for partial prefix
 *  matches. For example, when set and the key "dogs" is inserted, a search for
 *  "dog" or "do", or "d" will return `1`. Important to note, for one of
 *  these partial matches, the leaf node will not be returned so if a string
 *  was loaded at insertion time, it will not be returned.
 *
 *  Valid for \p fsmtrie_mode_ascii and \p fsmtrie_mode_eascii fsmtries.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 *  \param[in] key string to search for
 *  \param[out] str if key is found in a leaf node, str is a pointer to string
 *  stored at insertion time or NULL if no string is found
 *
 *  \retval 1 key exists in trie
 *  \retval 0 key not in trie
 *  \retval -1 error searching, call fsmtrie_get_error() to get the reason
 */
int fsmtrie_search(fsmtrie_t fsmtrie, const char *key, const char **str);
/* \cond */
int fsmtrie_search_ascii(fsmtrie_t fsmtrie, const char *key,
		const char **str);
int fsmtrie_search_eascii(fsmtrie_t fsmtrie, const char *key,
		const char **str);
/* \endcond */

/**
 *  Search a specified fsmtrie for a token key. If key is found, str may point
 *  to the string stored at insertion time.
 *
 *  Valid for \p fsmtrie_mode_token fsmtries.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 *  \param[in] key pointer to a token string to search for
 *  \param[in] keylen the number of tokens in the token key string
 *  \param[out] str if key is found, str is an optional pointer to string
 *  stored at insertion time
 *
 *  \retval 1 key exists in trie
 *  \retval 0 key not in trie
 *  \retval -1 error searching, call fsmtrie_get_error() to get the reason
 */
int fsmtrie_search_token(fsmtrie_t fsmtrie, const uint32_t *key,
		size_t keylen, const char **str);

/**
 * Search a specified fsmtrie for approximately matching keys that differ by at
 * most \p dist characters (this is a bounded edit distance search).
 *
 * Valid for \p fsmtrie_mode_ascii and \p fsmtrie_mode_eascii fsmtries.
 * 
 * The callback has the following prototype:
 *
 *`static void cb(const char *str, int dist, void *data);`
 *
 * where:
 * 	* \p str a pointer to the trie string that matched
 *	* \p dist the "edit distance" between str and the search term
 *	* \p data user supplied data
 *
 * \param[in] fsmtrie valid fsmtrie object
 * \param[in] key string to search for
 * \param[in] dist maximum allowed edit distance from key
 * \param[in] cb match callback function, called when a match is detected
 * \param[in] cbdata data passed to match callback function
 *
 *  \retval 1 function completed normally
 *  \retval -1 error searching, call fsmtrie_get_error() to get the reason
 */
int fsmtrie_search_approx(fsmtrie_t fsmtrie, const char *key, int dist,
		void (*cb)(const char *, int, void *), void *cbdata);

/**
 * Search a specified fsmtrie for matching substrings.
 *
 * Valid for \p fsmtrie_mode_ascii and \p fsmtrie_mode_eascii fsmtries.
 *
 * Uses Aho-Corasick for substring matching. The first time this function is
 * called, it incurs a performance penalty relative to the size of the fsmtrie
 * as it must first (and only once) compile a finite state machine building
 * links between various internal nodes.
 *
 * The time complexity of Aho-Corasick is linear in the length of the strings
 * plus the length of the searched text plus the number of output matches:
 * `O(n + m + z)`.
 *
 * The callback has the following prototype:
 *
 * `static void cb(const char *str, int off, void *data);`
 *
 * where:
 *	* \p str a pointer to the trie string that matched
 *	* \p off zero-indexed offset of str inside the search term
 *	* \p data user supplied data
 *
 * \param[in] fsmtrie valid fsmtrie object
 * \param[in] str string to search
 * \param[in] cb match callback function, called when a match is detected
 * \param[in] cbdata data passed to match callback function
 *
 *  \retval 1 function completed normally
 *  \retval -1 error searching, call fsmtrie_get_error() to get the reason
 */
int fsmtrie_search_substring(fsmtrie_t fsmtrie, const char *str,
		void (*cb)(const char *, int, void *), void *cbdata);

/**
 *  Cull the last error message from the library.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 *
 *  \returns pointer to a string containing the last error message or NULL if
 *  there was none.
 */
const char *fsmtrie_get_error(fsmtrie_t fsmtrie);

/* \cond */
/* backward compatibility with pre-release versions of library */
const char *fsmtrie_error(fsmtrie_t fsmtrie);
/* \endcond */

/**
 *  Print leaf node strings for a specified fsmtrie. This does not emit keys,
 *  just leaf node strings.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 */
void fsmtrie_print_leaves(fsmtrie_t fsmtrie);

/**
 *  Get node count of trie.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 */
uint32_t fsmtrie_get_nodecnt(fsmtrie_t fsmtrie);

/**
 *  Get key count of trie.
 *
 *  \param[in] fsmtrie valid fsmtrie object
 */
uint32_t fsmtrie_get_keycnt(fsmtrie_t fsmtrie);

/**
 * Retrieve the semantic library version as a string.
 */
const char *fsmtrie_get_version(void);

/**
 * Retrieve the semantic library version as a packed integer. The number is a
 * combination of the major, minor, and patchelevel numbers as per:
 * MAJOR * 1000000 + MINOR * 1000 + PATCHLEVEL.
 */
uint32_t fsmtrie_get_version_number(void);

/** @}*/
#endif
