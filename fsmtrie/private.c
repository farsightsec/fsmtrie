/*
 * Fast String Matcher Private Implementation
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

const char *
_mode_to_str(fsmtrie_mode mode)
{
	switch (mode)
	{
		case fsmtrie_mode_ascii:
			return ("ASCII");
		case fsmtrie_mode_eascii:
			return ("EASCII");
		case fsmtrie_mode_token:
			return ("TOKEN");
		default:
			return ("UNKNOWN");
	}
}
