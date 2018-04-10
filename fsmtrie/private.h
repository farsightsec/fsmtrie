/*
 * Fast String Matcher Private Interface
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

#ifndef FSMTRIE_PRIVATE_H
#define FSMTRIE_PRIVATE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include "fsmtrie.h"

/* forward */
struct fsmtrie;

/* size of an ASCII trie node, represents 128 ASCII code points */
#define FSMTRIE_SIZE_ASCII	128
/* size of an Extended ASCII trie node, represents 256 ASCII code points */
#define FSMTRIE_SIZE_EASCII	256
/* size of a newly initialized token trie node */
#define FSMTRIE_SIZE_TOKEN	1

/* a string inserted into the trie */
#define FSMTRIE_NODE_LEAF	1
/* a node whose path comprises a string which has had a proper suffix inserted
 * into the trie
 */
#define FSMTRIE_NODE_OUTPUT	2

/* fsmtrie options (mode and control flags) */
struct fsmtrie_opt
{
	fsmtrie_mode mode;
	uint8_t flags;
#define FSMTRIE_PM_OK           0x01    /* partial matches ok (ignore leaf) */
#define FSMTRIE_AC_COMPILED     0x02    /* Aho-Corasick metadata up to date */
	uint32_t max_len;		/* max key length (0 == unlimited) */
};

/* an fsmtrie node */
struct fsmtrie_node
{
	struct fsmtrie_node *suffix;	/* longest proper suffix node, if any */
	uint8_t type;			/* type of node */
	fsmtrie_mode mode;		/* copied from root parent */
	uint8_t flags;			/* copied from root parent */
	char *str;			/* optional leaf node string */
	uint32_t tval;			/* only used for tokens */
	uint16_t nnodes;		/* number of child nodes allocated */
	struct fsmtrie_node *nodes[]; 	/* a trie node */
};
typedef struct fsmtrie_node fsmtrie_node_t;

/* the fsmtrie and associated metadata */
struct fsmtrie
{
	uint16_t nrnodes;               /* node table size in trie */
	fsmtrie_node_t *root;		/* root node of trie */
	size_t node_cnt;		/* number of nodes in trie */
	size_t key_cnt;			/* number of keys in trie */
	uint32_t max_len;		/* max key length (0 == no max) */
	fsmtrie_mode mode;		/* mode of operation */
	uint8_t flags;			/* control flags */
	char err_buf[BUFSIZ];		/* error messages go here */
	uint8_t pad[1];			/* pad to even bb */
};

/* convert mode to a string */
const char * _mode_to_str(fsmtrie_mode mode);

#endif
