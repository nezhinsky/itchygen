/*
 * File: ulist.c
 * Summary: double linked list (+ upcasting routines)
 *
 * Author: Rusty Russell <rusty@rustcorp.com.au>
 * Modified by: Alexander Nezhinsky (nezhinsky@gmail.com)
 *
 * Licensed under BSD-MIT :
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "ulist.h"

static void *corrupt(const char *abortstr,
		     const struct ulist_node *head,
		     const struct ulist_node *node, unsigned int count)
{
	if (abortstr) {
		fprintf(stderr,
			"%s: prev corrupt in node %p (%u) of %p\n",
			abortstr, node, count, head);
		abort();
	}
	return NULL;
}

struct ulist_node *ulist_check_node(const struct ulist_node *node,
				    const char *abortstr)
{
	const struct ulist_node *p, *n;
	int count = 0;

	for (p = node, n = node->next; n != node; p = n, n = n->next) {
		count++;
		if (n->prev != p)
			return corrupt(abortstr, node, n, count);
	}
	/* Check prev on head node. */
	if (node->prev != p)
		return corrupt(abortstr, node, node, 0);

	return (struct ulist_node *)node;
}

struct ulist_head *ulist_check(const struct ulist_head *h, const char *abortstr)
{
	if (!ulist_check_node(&h->n, abortstr))
		return NULL;
	return (struct ulist_head *)h;
}
