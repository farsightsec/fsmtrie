/*
 * Fast String Matcher Public Implementation
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

#include "private.h"

/* export */

/* create a new empty trie node */
static fsmtrie_node_t *
_fsmtrie_node_new(fsmtrie_mode mode, uint8_t flags, uint16_t *pnnodes)
{
	fsmtrie_node_t *result;
	size_t nnodes, alloc_size;

	switch (mode)
	{
		case fsmtrie_mode_ascii:
			nnodes = FSMTRIE_SIZE_ASCII;
			break;
		case fsmtrie_mode_eascii:
			nnodes = FSMTRIE_SIZE_EASCII;
			break;
		case fsmtrie_mode_token:
			nnodes = FSMTRIE_SIZE_TOKEN;
			break;
		default:
			/* this should never happen */
			return (NULL);
	}

	alloc_size = sizeof (fsmtrie_node_t) * (nnodes + 1);
	result = (fsmtrie_node_t *)calloc(1, alloc_size);
	result->mode = mode;
	result->flags = flags;

	if (pnnodes != NULL)
	{
		*pnnodes = nnodes;
	}

	return (result);
}

const char *
fsmtrie_error(struct fsmtrie *f)
{
	return (fsmtrie_get_error(f));
}

const char *
fsmtrie_get_error(struct fsmtrie *f)
{
	return (f->err_buf);
}

struct fsmtrie *
fsmtrie_init(struct fsmtrie_opt *o, char *err_buf)
{
	struct fsmtrie *f;
	fsmtrie_mode mode;
	uint8_t flags;
	uint32_t max_len;

	f = calloc(1, sizeof (struct fsmtrie));
	if (f == NULL)
	{
		snprintf(err_buf, BUFSIZ - 1, "can't allocate fsmtrie: %s",
				strerror(errno));
		return (NULL);
	}

	if (o == NULL)
	{
		mode = fsmtrie_mode_ascii;
		flags = 0;
		max_len = 0;
	}
	else
	{
		max_len = o->max_len;
		mode = o->mode;
		flags = o->flags;
	}

	switch (mode)
	{
		case fsmtrie_mode_ascii:
		case fsmtrie_mode_eascii:
			f->root = _fsmtrie_node_new(mode, flags, &f->nrnodes);
			break;
		case fsmtrie_mode_token:
			if (flags & FSMTRIE_PM_OK)
			{
				snprintf(err_buf, BUFSIZ - 1,
						"partial match not allowed for"
					        " token fsmtries");
				free(f);
				return (NULL);
			}
			f->root = _fsmtrie_node_new(mode, flags, NULL);
			f->nrnodes = 0;
			break;
		default:
			snprintf(err_buf, BUFSIZ - 1,
					"unrecognized mode \"%d\"", mode);
			free(f);
			return (NULL);
	}

	if (f->root == NULL)
	{
		snprintf(err_buf, BUFSIZ - 1, "can't allocate root node: %s",
				strerror(errno));
		free(f);
		return (NULL);
	}

	f->max_len = max_len;
	f->mode = mode;
	f->flags = flags;

	return (f);
}

struct fsmtrie_opt *
fsmtrie_opt_init(void)
{
	struct fsmtrie_opt *o;

	o = calloc(1, sizeof(*o));
	if (o == NULL)
	{
		return (NULL);
	}

	o->mode = fsmtrie_mode_ascii;
	o->flags = 0;
	o->max_len = 0;

	return (o);
}

void
fsmtrie_opt_free(struct fsmtrie_opt *o)
{
	if (o != NULL)
	{
		free(o);
	}
}

void
fsmtrie_opt_destroy(struct fsmtrie_opt **o)
{
	fsmtrie_opt_free(*o);

	*o = NULL;
}

bool
fsmtrie_opt_set_mode(struct fsmtrie_opt *o, fsmtrie_mode mode)
{
	if (o == NULL)
	{
		return (false);
	}

	o->mode = mode;

	return (true);
}

bool
fsmtrie_opt_get_mode(struct fsmtrie_opt *o, fsmtrie_mode *mode)
{
	if (o == NULL)
	{
		return (false);
	}

	*mode = o->mode;

	return (true);
}

bool
fsmtrie_opt_set_maxlength(struct fsmtrie_opt *o, uint32_t max_len)
{
	if (o == NULL)
	{
		return (false);
	}

	o->max_len = max_len;

	return (true);
}

bool
fsmtrie_opt_get_maxlength(struct fsmtrie_opt *o, uint32_t *max_len)
{
	if (o == NULL)
	{
		return (false);
	}

	*max_len = o->max_len;

	return (true);
}

bool
fsmtrie_opt_set_partialmatch(struct fsmtrie_opt *o, bool on)
{
	if (o == NULL)
	{
		return (false);
	}

	if (on == true)
	{
		o->flags &= ~FSMTRIE_PM_OK;
		o->flags |= FSMTRIE_PM_OK;
	}
	else
	{
		o->flags &= ~FSMTRIE_PM_OK;
	}

	return (true);
}

bool
fsmtrie_opt_get_partialmatch(struct fsmtrie_opt *o, bool *on)
{
	if (o == NULL)
	{
		return (false);
	}

	*on = (o->flags & FSMTRIE_PM_OK) == true;

	return (true);
}

bool
fsmtrie_key_validate_ascii(struct fsmtrie *f, const char *key)
{
	size_t n;
	const unsigned char *p;

	if (f == NULL)
	{
		return (false);
	}
	if (f->root == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "uninitialized trie");
		return (false);
	}

	if (key == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "empty key");
		return (false);
	}

	if (f->max_len > 0)
	{
		if ((n = strlen(key)) > f->max_len)
		{
			snprintf(f->err_buf, sizeof (f->err_buf),
					"key too long (%ld > %d)",
					n, f->max_len);
			return (false);
		}
	}
	if (f->mode == fsmtrie_mode_ascii)
	{
		for (n = 0, p = (unsigned char *)key; *p; n++, p++)
		{
			/* store only ASCII code points */
			if ((int)*p < 0 || (int)*p > f->nrnodes - 1)
			{
				snprintf(f->err_buf,
						sizeof (f->err_buf),
					"\"%d\" value at position %ld"
					" out of range", (int)*p, n);
				return (false);
			}
		}
	}
	return (true);
}

bool
fsmtrie_insert_ascii(struct fsmtrie *f, const char *key, const char *str)
{
	return (fsmtrie_insert(f, key, str));
}

bool
fsmtrie_insert_eascii(struct fsmtrie *f, const char *key, const char *str)
{
	return (fsmtrie_insert(f, key, str));
}

/*
 * XXX: In the unlikely event we return false mid-way through adding a key
 * the library will leave an unfinished insertion in the trie which amounts to
 * a sort of memory leak. But if the process runs out of memory, you probably
 * have bigger problems.
 */
bool
fsmtrie_insert(struct fsmtrie *f, const char *key, const char *str)
{
	int len;
	const unsigned char *p;
	fsmtrie_node_t *node_p;

	if (f == NULL)
	{
		return (false);
	}
	if (f->root == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf),
				"uninitialized trie");
		return (false);
	}

	if (f->mode != fsmtrie_mode_ascii && f->mode != fsmtrie_mode_eascii)
	{
		snprintf(f->err_buf,
				sizeof (f->err_buf),
				"%s() is incompatible with %s mode fsmtrie",
				__func__, _mode_to_str(f->mode));
		return (false);
	}

	/* Validate the string before adding to trie to avoid partial adds
	 * when encountering invalid code points mid way through a key.
	 */
	if (!fsmtrie_key_validate_ascii(f, key))
	{
		/* f->err_buf set by fsmtrie_key_validate_ascii() */
		return (false);
	}

	/* Walk the trie from the root, adding the key char by char. Duplicate
	 * keys will not be re-added.
	 */
	for (p = (unsigned char *)key, node_p = f->root; *p; p++)
	{
		if (node_p->nodes[(int)*p] == NULL)
		{
			/* create a new node at the code point's index */
			node_p->nodes[(int)*p] =
				_fsmtrie_node_new(f->mode, f->flags, NULL);
			node_p->nodes[(int)*p]->nnodes = f->nrnodes;
			if (node_p->nodes[(int)*p] == NULL)
			{
				snprintf(f->err_buf,
						sizeof (f->err_buf),
						"can't add node: %s",
						strerror(errno));
				return (false);
			}
			f->node_cnt++;
		}
		node_p = node_p->nodes[(int)*p];
	}

	if (node_p->type & FSMTRIE_NODE_LEAF)
	{
		/* This is a duplicate key, return immediately without error.
		 * We don't bump the key count nor add the string (if one
		 * is provided). This might change if we add a node reference
		 * count and provide a mechanism for storing and culling
		 * multiple str's.
		 */
		return (true);
	}
	/* The last node is marked as a leaf so "dog" will be distinct
	 * from "dogs" if *not* allowing partial matches (FSMTRIE_PM_OK).
	 */
	node_p->type |= (FSMTRIE_NODE_LEAF | FSMTRIE_NODE_OUTPUT);
	if (str)
	{
		len = strlen(str) + 1;
		node_p->str = calloc(1, len);
		if (node_p->str == NULL)
		{
			snprintf(f->err_buf,
					sizeof (f->err_buf),
					"can't add node str: %s",
					strerror(errno));
			return (false);
		}
		strlcpy(node_p->str, str, len);
	}
	/* The trie needs Aho-Corasick info updated after insertion. */
	f->flags &= ~FSMTRIE_AC_COMPILED;

	f->key_cnt++;
	return (true);
}

/*
 * Use a binary search to find the specified token inside an array of token
 * nodes. If do_insert is set, resize the nodes group and insert the new node
 * if token cannot be found.
 *
 * If not NULL, store the resulting index into the address of pidx.
 */
static int
_fsmtrie_get_token_idx(fsmtrie_node_t **nodep, size_t nodecnt, uint32_t token,
		bool do_insert, size_t *pidx)
{
	size_t alloc_size;
	ssize_t slow, shigh, sidx;

	slow = 0;
	shigh = nodecnt - 1;
	sidx = nodecnt == 0 ? -1 : 0;

	while (sidx != -1)
	{
		unsigned int sval;

		sidx = ((shigh - slow) + 1) / 2 + slow;
		sval = (*nodep)->nodes[sidx]->tval;

		if (sval == token)
		{
			if (pidx != NULL)
			{
				*pidx = sidx;
			}
			return (0);
		}

		if (slow == shigh)
		{
			break;
		}

		if (sval < token)
		{
			slow = sidx + 1;
		}
		else if (sval > token)
		{
			shigh = sidx - 1;
		}

		if ((slow > shigh) || (shigh < slow))
		{
			break;
		}
	}

	if (sidx < 0)
	{
		sidx = 0;
	}
	else if (token > (*nodep)->nodes[sidx]->tval)
	{
		sidx++;
	}

	if (!do_insert)
	{
		return (-1);
	}

	alloc_size = sizeof(*nodep) + (sizeof(**nodep) * (nodecnt + 1));
	*nodep = realloc(*nodep, alloc_size);
	memmove(&((*nodep)->nodes[sidx + 1]),
			&((*nodep)->nodes[sidx]),
			sizeof(**nodep) * (nodecnt - sidx));
	(*nodep)->nodes[sidx] = NULL;

	if (pidx)
	{
		*pidx = sidx;
	}

	return (1);
}

/*
 * Store a special kind of "token string" in a trie that consists of a sequence of
 * 32-bit values.
 *
 * Subsequent searchest must be performed using fsmtrie_search_token().
 */
bool
fsmtrie_insert_token(struct fsmtrie *f, uint32_t *tkey, size_t nkey, const char *str)
{
	fsmtrie_node_t *node_p, *last_parent;
	size_t tokidx, last_idx;
	int len;

	if (f == NULL)
	{
		return (false);
	}
	if (f->root == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "uninitialized trie");
		return (false);
	}

	if (f->mode != fsmtrie_mode_token)
	{
		snprintf(f->err_buf,
				sizeof (f->err_buf),
				"%s() is incompatible with %s mode fsmtrie",
				__func__, _mode_to_str(f->mode));
		return (false);
	}

	if (f->max_len > 0)
	{
		if (nkey > f->max_len)
		{
			snprintf(f->err_buf, sizeof (f->err_buf),
					"token string too long (%ld > %d)",
					nkey, f->max_len);
			return (false);
		}
	}

	/* Walk the trie from the root, adding the key token by token. Duplicate
	 * keys will not be re-added.
	 */
	for (node_p = f->root, last_parent = NULL, tokidx = 0;
			tokidx < nkey; tokidx++)
	{
		fsmtrie_node_t *node_pp = node_p; 
		int ires;
		size_t nidx, nnodes;

		nnodes = (last_parent == NULL) ? f->nrnodes :
			node_pp->nnodes;
		ires = _fsmtrie_get_token_idx(&node_pp, nnodes, tkey[tokidx],
				true, &nidx);

		if (ires < 0)
		{
			snprintf(f->err_buf, sizeof (f->err_buf),
					"can't insert token into node");
			return (false);
		}
		else if (ires > 0)
		{
			/* create a new node at the code point's index */
			node_pp->nodes[nidx] = _fsmtrie_node_new(node_pp->mode,
					node_pp->flags, NULL);

			if (node_pp->nodes[nidx] == NULL)
			{
				snprintf(f->err_buf,
						sizeof (f->err_buf),
						"can't add node: %s",
						strerror(errno));
				return (false);
			}

			node_pp->nodes[nidx]->tval = tkey[tokidx];
			node_pp->nodes[nidx]->mode = f->mode;
			node_pp->nodes[nidx]->flags = f->flags;

			/* The new node is initialized with nnodes = 0
			 * but its parent will need to have its node count
			 * incremented.
			 */
			if (last_parent == NULL)
			{
				f->nrnodes++;
			}
			else
			{
				node_pp->nnodes++;
			}

			/* If we've reallocated ourselves we will need to
			 * update our parent's reference.
			 */
			if (node_pp != node_p)
			{
				if (last_parent == NULL)
				{
					f->root = node_pp;
				}
				else
				{
					last_parent->nodes[last_idx] = node_pp;
				}
			}
		}

		last_parent = node_pp;
		last_idx = nidx;
		node_p = node_pp->nodes[nidx];
	}

	/* This is a duplicate key, return immediately without error. */
	if (node_p->type & FSMTRIE_NODE_LEAF)
	{
		return (true);
	}

	node_p->type |= (FSMTRIE_NODE_LEAF | FSMTRIE_NODE_OUTPUT);
	if (str)
	{
		len = strlen(str) + 1;
		node_p->str = calloc(1, len);
		if (node_p->str == NULL)
		{
			snprintf(f->err_buf,
					sizeof (f->err_buf),
					"can't add node str: %s",
					strerror(errno));
			return (false);
		}
		strlcpy(node_p->str, str, len);
	}
	f->node_cnt++;
	/* The trie needs Aho-Corasick info updated after insertion. */
	f->flags &= ~FSMTRIE_AC_COMPILED;

	f->key_cnt++;
	return (true);
}

/* recursively print trie leaves to stdout */
static void
_fsmtrie_print_leaves(fsmtrie_node_t *node, unsigned int depth)
{
	int n;
	fsmtrie_node_t *node_p;

	for (n = 0, node_p = node; n < node->nnodes; n++)
	{
		if (node_p->nodes[n] != NULL)
		{
			_fsmtrie_print_leaves(node_p->nodes[n], depth + 1);
		}
	}
	if (node_p->mode == fsmtrie_mode_token)
	{
		size_t q;
		for (q = 0; q < depth - 1; q++)
		{
			printf(" ");
		}
	}
	if ((node_p->type & FSMTRIE_NODE_LEAF) && node_p->str != NULL)
	{
		if (node_p->mode == fsmtrie_mode_token)
		{
			printf("%u = [%s]\n", node_p->tval, node_p->str);
		}
		else
		{
			printf("%s\n", node_p->str);
		}
	}
	else if (node_p->mode == fsmtrie_mode_token)
	{
		printf("%u\n", node_p->tval);
	}
}

void
fsmtrie_print_leaves(struct fsmtrie *f)
{
	int n;
	fsmtrie_node_t *node_p;

	if (f == NULL)
	{
		return;
	}
	if (f->root == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "uninitialized trie");
		return;
	}

	for (n = 0, node_p = f->root; n < f->nrnodes; n++)
	{
		if (node_p->nodes[n] != NULL)
		{
			_fsmtrie_print_leaves(node_p->nodes[n], 1);
		}
	}
}

/* recursively free trie branches */
static void
_fsmtrie_release_branch(fsmtrie_node_t *node)
{
	int n;
	fsmtrie_node_t *node_p;

	for (n = 0, node_p = node; n < node->nnodes; n++)
	{
		if (node_p->nodes[n])
		{
			_fsmtrie_release_branch(node_p->nodes[n]);
		}
	}
	if ((node_p->type & FSMTRIE_NODE_LEAF) && node_p->str != NULL)
	{
		free(node_p->str);
		node_p->str = NULL;
	}
	free(node);
}

void
fsmtrie_free(struct fsmtrie *f)
{
	int n;
	fsmtrie_node_t *root;

	if (f == NULL || f->root == NULL)
	{
		return;
	}

	root = f->root;

	/* Freeing the trie is recursive. Walk from the root, each time a node
	 * is encountered, call the recursive freeing function. When the node
	 * list is exhausted, free it.
	 */
	for (n = 0; n < f->nrnodes; n++)
	{
		if (root->nodes[n] != NULL)
		{
			_fsmtrie_release_branch(root->nodes[n]);
		}
	}

	if (root->str != NULL)
	{
		free(root->str);
		root->str = NULL;
	}

	/* free top-level node */
	free(root);

	f->root = NULL;
	f->node_cnt = 0;
}

void
fsmtrie_destroy(struct fsmtrie **f)
{
	fsmtrie_free(*f);

	free(*f);
	*f = NULL;
}

int
fsmtrie_search_ascii(struct fsmtrie *f, const char *key, const char **str)
{
	return (fsmtrie_search(f, key, str));
}

int
fsmtrie_search_eascii(struct fsmtrie *f, const char *key, const char **str)
{
	return (fsmtrie_search(f, key, str));
}

int
fsmtrie_search(struct fsmtrie *f, const char *key, const char **str)
{
	const unsigned char *p;
	fsmtrie_node_t *node_p;

	if (f == NULL)
	{
		return (-1);
	}
	if (f->root == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "uninitialized trie");
		return (-1);
	}

	if (key == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "empty key");
		return (-1);
	}

	if (f->mode != fsmtrie_mode_ascii && f->mode != fsmtrie_mode_eascii)
	{
		snprintf(f->err_buf,
				sizeof (f->err_buf),
				"%s() is incompatible with %s mode fsmtrie",
				__func__, _mode_to_str(f->mode));
		return (-1);
	}

	*str = NULL;
	for (p = (const unsigned char *)key, node_p = f->root; *p; p++)
	{
		/* same check fsmtrie_key_validate_ascii() does but we don't
		 * want to walk the entire key twice so we don't call the
		 * function and instead do this check here.
		 */
		if ((int)*p < 0 || (int)*p > f->nrnodes - 1)
		{
			snprintf(f->err_buf,
				sizeof (f->err_buf),
				"key value \"%d\" out of range",
				(int)*p);
			return (-1);
		}
		if (node_p->nodes[(int)*p] == NULL)
		{
			/* no match */
			return (0);
		}

		node_p = node_p->nodes[(int)*p];
	}
	if (node_p->type & FSMTRIE_NODE_LEAF)
	{
		*str = node_p->str;
	}

	if (node_p != NULL && (f->flags & FSMTRIE_PM_OK) ? true :
			(node_p->type & FSMTRIE_NODE_LEAF))
	{
		return (1);
	}
	return (0);
}

/* Search for a specified token array using a binary search */
int
fsmtrie_search_token(struct fsmtrie *f, const uint32_t *key, size_t keylen,
		const char **str)
{
	uint32_t pkey;
	fsmtrie_node_t *node_p;
	size_t keyidx;

	if (f == NULL)
	{
		return (-1);
	}
	if (f->root == NULL)
	{
		snprintf(f->err_buf, sizeof (f->err_buf), "uninitialized trie");
		return (-1);
	}

	if (key == NULL || keylen == 0)
	{
		snprintf(f->err_buf,
				sizeof (f->err_buf),
				"empty key or keylen");
		return (-1);
	}

	if (f->mode != fsmtrie_mode_token)
	{
		snprintf(f->err_buf,
				sizeof (f->err_buf),
				"%s() is incompatible with %s mode fsmtrie",
				__func__, _mode_to_str(f->mode));
		return (-1);
	}

	for (keyidx = 0, node_p = f->root, *str = NULL; keyidx < keylen;
			keyidx++)
	{
		size_t nnodes;
		ssize_t slow, shigh, sidx;

		nnodes = (node_p == f->root) ? f->nrnodes : node_p->nnodes;
		pkey = key[keyidx];

		slow = 0;
		shigh = nnodes - 1;
		sidx = nnodes == 0 ? -1 : 0;

		while (sidx != -1)
		{
			unsigned int sval;

			sidx = ((shigh - slow) + 1) / 2 + slow;
			sval = node_p->nodes[sidx]->tval;

			if ((sval == pkey) || (slow == shigh))
			{
				break;
			}
			else if (sval < pkey)
			{
				slow = sidx + 1;
			}
			else if (sval > pkey)
			{
				shigh = sidx - 1;
			}

			if ((slow > shigh) || (shigh < slow))
			{
				break;
			}
		}

		if ((sidx == -1) || (node_p->nodes[sidx]->tval != pkey))
		{
			return (0);
		}

		node_p = node_p->nodes[sidx];
	}
	if (node_p->type & FSMTRIE_NODE_LEAF)
	{
		*str = node_p->str;
	}

	if (node_p != NULL && (node_p->type & FSMTRIE_NODE_LEAF))
	{
		return (1);
	}

	return (0);
}

uint32_t
fsmtrie_get_keycnt(struct fsmtrie *f)
{
	return (f->key_cnt);
}

uint32_t
fsmtrie_get_nodecnt(struct fsmtrie *f)
{
	return (f->node_cnt);
}
