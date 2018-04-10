/*
 * Fast String Matcher Approximate Searching Implementation
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

/* \cond */
/*
 * Efficiently calculating a bounded edit distance (i.e., where we
 * do not care about the distance if it is greater than some number) is
 * possible using a sparse integer matrix of interim results. The sparse
 * matrix usage in this algorithm supports a simple sorted append-only
 * representation.
 *
 * We represent entries as index, value pairs. A separate row structure
 * points to a location in an array of entries, with a length.
 */
struct sim_entry
{
	int index, value;
};

struct sim_row
{
	struct sim_entry *start;
	int len;
};
/* \endcond */

static bool
sim_row_append(struct sim_row *row, struct sim_entry *end, int index, int value)
{
	if (&row->start[row->len] < end)
	{
		row->start[row->len].index = index;
		row->start[row->len].value = value;
		row->len++;
		return (true);
	}
	return (false);
}

static void
sim_row_first(struct sim_row *first, struct sim_entry *start)
{
	first->len = 0;
	first->start = start;
}

/* Prepare the next row for entries. */
static bool
sim_row_next(struct sim_row *row, struct sim_row *next, struct sim_entry *end)
{
	if (&row->start[row->len] < end)
	{
		next->len = 0;
		next->start = &row->start[row->len];
		return (true);
	}
	return (false);
}

/*
 * Retrieve the index and value of the i-th element of the row.
 * Returns fales if there is no i-th element.
 */
static bool
sim_row_elem(struct sim_row *row, int i, int *index, int *value)
{
	if (i < row->len)
	{
		*index = row->start[i].index;
		*value = row->start[i].value;
		return (true);
	}
	return (false);
}

/*
 * Retrieve the index and value of the last element of the row.
 * Returns false if there are no entries in the row.
 */
static bool
sim_row_last(struct sim_row *row, int *index, int *value)
{
	return ((row->len > 0) && sim_row_elem(row, row->len-1, index, value));
}

/*
 * Traverse the trie searching for elements with an edit distance of
 * at most max_dist from the supplied key. The edit distance implemented
 * here is the "optimal string alignment" variant of the Levenshtein distance,
 * in which transposition of adjacent characters are counted as a single
 * edit, rather than a deletion and insertion in standard Levenshtein.
 */
int
fsmtrie_search_approx(struct fsmtrie *f, const char *key, int max_dist,
		void (*cb)(const char *, int, void *), void *cbdata)
{
	const unsigned char *key_u = (unsigned char *)key;

	if (f->max_len == 0)
	{
		snprintf(f->err_buf,
			sizeof (f->err_buf),
			"%s() requires fsmtrie to be initialized with max_len",
			__func__);
                return (-1);
	}

	if (f->mode == fsmtrie_mode_token)
	{
		snprintf(f->err_buf,
			sizeof (f->err_buf),
			"%s() is incompatible with %s mode fsmtrie",
			__func__, _mode_to_str(f->mode));
                return (-1);
	}

	int keylen = strlen(key);
	int mlen = (2 * max_dist + 1) * (f->max_len + 1);

	struct sim_entry matrix[mlen], *end = &matrix[mlen];
	struct sim_row rows[f->max_len + 1];

	/* node and character stacks */
	fsmtrie_node_t *nodes[f->max_len + 1];
	unsigned char chars[keylen + 1];

	int c, i, j, k, index, value;
	fsmtrie_node_t *node, *child;

	sim_row_first(&rows[0], &matrix[0]);

	for (j = 0; j <= max_dist && j < (int)f->max_len; j++)
	{
		assert(sim_row_append(&rows[0], end, j, j));
	}

	node = f->root;
	nodes[0] = NULL;
	chars[0] = 0;
	i = 0;

	while (node)
	{
		for (c = chars[i]; c < f->nrnodes; c++)
		{
			if (node->nodes[c] == NULL)
			{
				continue;
			}
			child = node->nodes[c];

			assert(sim_row_next(&rows[i], &rows[i+1], end));

			/* If the 0-th element in the next row is in bounds,
			   generate it. */
			if (i < max_dist)
			{
				assert(sim_row_append(&rows[i+1], end, 0, i+1));
			}

			for (j = 0; sim_row_elem(&rows[i], j, &index, &value);
					j++)
			{
				int lindex, lvalue;
				int cost = (c == key_u[index])? 0 : 1;
				int dist = value + cost;

				/* adjacent previous element in next row. */
				if (sim_row_last(&rows[i+1], &lindex, &lvalue))
				{
					if ((lindex == index) &&
							(lvalue + 1 < dist))
					{
						dist = lvalue + 1;
					}
				}

				/* element directly above next element in
				 * next row. */
				if (sim_row_elem(&rows[i], j + 1, &lindex,
							&lvalue))
				{
					if ((lindex == index + 1) &&
							(lvalue + 1 < dist))
					{
						dist = lvalue + 1;
					}
				}

				/* Count a transposition as a single change
				 * from the previous element in the previous
				 * row. */
				if (i > 0 && index > 0 &&
					(key_u[index] == chars[i-1] - 1) &&
					(key_u[index-1] == c))
				{
					for (k = 0; sim_row_elem(&rows[i-1], k,
								&lindex,
								&lvalue); k++)
					{
						if (lindex >= index)
						{
							break;
						}
						if ((lindex == index-1) &&
								(lvalue +
								 cost < dist))
						{
							dist = lvalue + cost;
						}
					}
				}

				/* if the minimum of the three cases above is
				 * in bounds, append it to next row. */
				if (dist <= max_dist && index < keylen)
				{
					assert(sim_row_append(&rows[i+1],
								end,
								index + 1,
								dist));
				}
			}

			if (!sim_row_elem(&rows[i + 1], 0, &index, &value))
			{
				/* Adding this character increased the
				   Levenshtein distance over our limit.
				   Prune search here, go on to next child. */
				continue;
			}

			if (child->type & FSMTRIE_NODE_LEAF)
			{
				/* Adding this character results in a string
				   which was inserted into the trie, and at
				   least a prefix of the key is within our
				   Levenshtein distance limit of the string.
				   Check if the full key is within the distance
				   limit and, if so, call the callback. */
				if (sim_row_last(&rows[i + 1], &index, &value))
				{
					if (index == keylen)
					{
						cb(child->str, value, cbdata);
					}
				}
			}


			if (i < (int)f->max_len)
			{
				/* If the child node could have children,
				   save our current node and character,
				   and restart the loop over the child's
				   children. */
				chars[i++] = c + 1;
				nodes[i] = node;
				node = child;
				c = 0;
				chars[i] = 0;
			}
		}

		/* done iterating, restore the previous (parent) node. */
		node = nodes[i--];
        }
	return (1);
}
