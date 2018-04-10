/*
 * Fast String Matcher Substring Matching Implementation
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
 * Calculating Aho-Corasick metadata efficiently involves a breadth-first
 * trie traversal, which requires a queue of trie nodes to organize.
 */
struct _fsmtrie_nodeq {
        int size, head, tail;
        fsmtrie_node_t **queue;
};
/* \endcond */

static bool
_fsmtrie_nodeq_init(struct _fsmtrie_nodeq *q, int size)
{
        q->queue = calloc(size, sizeof(fsmtrie_node_t *));
        if (q->queue == NULL)
        {
                return false;
        }
        q->size = size;
        q->head = q->tail = 0;
        return true;
}

static void
_fsmtrie_nodeq_destroy(struct _fsmtrie_nodeq *q)
{
        free(q->queue);
}

static bool
_fsmtrie_nodeq_empty(struct _fsmtrie_nodeq *q)
{
        return q->head == q->tail;
}

static bool
_fsmtrie_nodeq_enqueue(struct _fsmtrie_nodeq *q, fsmtrie_node_t *n) {
        int next = (q->tail + 1) % q->size;
        if (next == q->head) {
                /* queue full */
                return false;
        }
        q->queue[q->tail] = n;
        q->tail = next;
        return true;
}

static fsmtrie_node_t *
_fsmtrie_nodeq_dequeue(struct _fsmtrie_nodeq *q) {
        fsmtrie_node_t *n;
        int next = (q->head + 1) % q->size;
        if (q->head == q->tail)
                return NULL;
        n = q->queue[q->head];
        q->head = next;
        return n;
}

static void
_fsmtrie_ac_compile(struct fsmtrie *f)
{
        fsmtrie_node_t *node, *child, *suffix;
        struct _fsmtrie_nodeq queue;
        int c;

        /*
         * During the traversal, the queue will contain less than two
         * levels of the trie. Each level of the trie contains at most
         * a number of nodes equal to the leaf nodes (inserted strings)
         * in the trie. This provides an upper bound for the queue length.
         */
        assert(_fsmtrie_nodeq_init(&queue, 2 * f->node_cnt));

        /*
         * The root node has no proper suffix. The single-character
         * nodes have no nonempty proper suffixes, but the root node
         * is their empty proper suffix.
         */
        f->root->suffix = NULL;
        for (c = 0; c < f->nrnodes; c++)
        {
                if (f->root->nodes[c] == NULL)
                        continue;
                f->root->nodes[c]->suffix = f->root;
                assert(_fsmtrie_nodeq_enqueue(&queue, f->root->nodes[c]));
        }

        while (!_fsmtrie_nodeq_empty(&queue))
        {
                node = _fsmtrie_nodeq_dequeue(&queue);
                assert(node != NULL);
                for (c = 0; c < f->nrnodes; c++) {

                        if (node->nodes[c] == NULL)
                                continue;

                        child = node->nodes[c];
                        assert(_fsmtrie_nodeq_enqueue(&queue, child));

                        child->suffix = f->root;
                        if (child->type & FSMTRIE_NODE_LEAF)
                                child->type |= FSMTRIE_NODE_OUTPUT;
                        else
                                child->type &= ~FSMTRIE_NODE_OUTPUT;


                        /*
                         *  Traverse the parent's suffixes to find the longest
                         *  suffix for the child node.
                         */
                        for (suffix = node->suffix; suffix; suffix = suffix->suffix)
                        {
                                if (suffix->nodes[c] == NULL)
                                        continue;
                                child->suffix = suffix->nodes[c];
                                if (child->suffix->type & FSMTRIE_NODE_OUTPUT)
                                        child->type |= FSMTRIE_NODE_OUTPUT;
                                break;
                        }

                }
        }
        _fsmtrie_nodeq_destroy(&queue);
        f->flags |= FSMTRIE_AC_COMPILED;
}

int
fsmtrie_search_substring(struct fsmtrie *f, const char *str,
                        void (*cb)(const char *, int, void *), void *cbdata)
{
        fsmtrie_node_t *node, *next, *n;
        const unsigned char *c;

	if (f->mode == fsmtrie_mode_token)
	{
		snprintf(f->err_buf,
			sizeof (f->err_buf),
			"%s() is incompatible with %s mode fsmtrie",
			__func__, _mode_to_str(f->mode));
		return (-1);
	}

        assert(f->root);

        if ((f->flags & FSMTRIE_AC_COMPILED) == 0)
                _fsmtrie_ac_compile(f);

        node = f->root;
        for (c = (unsigned char *)str; *c; c++) {
                next = node->nodes[(int)*c];

                /*
                 * If our current path does not continue, walk the list of
                 * suffixes to find the next node. If no suffixes continue
                 * with the next character, restart at the root.
                 */
                while (next == NULL)
                {
                        node = node->suffix;
                        if (node == NULL)
                                next = f->root;
                        else
                                next = node->nodes[(int)*c];
                }
                node = next;

                if (node->type & FSMTRIE_NODE_OUTPUT)
                {
                        /*
                         *  Traverse the suffix list. Any leaf node on this
                         *  list is a match.
                         */
                        for (n = node; n; n = n->suffix)
                        {
                                if (n->type & FSMTRIE_NODE_LEAF) {
					/*
					 * amoff is the offset in the subject
					 * string of the first character after
					 * the match. moff is the offset of
					 * the match string in the subject
					 * string.
					 */
					int amoff = (int)(c - (unsigned char *)str) + 1;
					int moff = amoff - strlen(n->str);
                                        cb(n->str, moff, cbdata);
				}
                        }
                }
        }
	return (1);
}
