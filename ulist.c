/* Licensed under BSD-MIT - see LICENSE file for details */
#include <stdio.h>
#include <stdlib.h>
#include "ulist.h"

static void *corrupt(const char *abortstr,
		     const struct ulist_node *head,
		     const struct ulist_node *node,
		     unsigned int count)
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
