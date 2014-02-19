/*
 * File: ulist.h
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

#ifndef __ULIST_H_
#define __ULIST_H_

#include <stdbool.h>
#include <stddef.h>
#include <assert.h>

__BEGIN_DECLS
// #define __ULIST_DEBUG_
/**
 * check_type - issue a warning or build failure if type is not correct.
 * @expr: the expression whose type we should check (not evaluated).
 * @type: the exact type we expect the expression to be.
 *
 * This macro is usually used within other macros to try to ensure that a macro
 * argument is of the expected type.  No type promotion of the expression is
 * done: an unsigned int is not the same as an int!
 *
 * check_type() always evaluates to 0.
 *
 * Example:
 *	// They should always pass a 64-bit value to _set_some_value!
 *	#define set_some_value(expr)			\
 *		_set_some_value((check_type((expr), uint64_t), (expr)))
 */
#define check_type(expr, type) \
	((typeof(expr) *)0 != (type *)0)
/**
 * check_types_match - issue a warning or build failure if types are not same.
 * @expr1: the first expression (not evaluated).
 * @expr2: the second expression (not evaluated).
 *
 * This macro is usually used within other macros to try to ensure that
 * arguments are of identical types.  No type promotion of the expressions is
 * done: an unsigned int is not the same as an int!
 *
 * check_types_match() always evaluates to 0.
 *
 * Example:
 *	// Do subtraction to get to enclosing type, but make sure that
 *	// pointer is of correct type for that member.
 *	#define ucontainer_of(mbr_ptr, encl_type, mbr)			\
 *		(check_types_match((mbr_ptr), &((encl_type *)0)->mbr),	\
 *		 ((encl_type *)						\
 *		  ((char *)(mbr_ptr) - offsetof(enclosing_type, mbr))))
 */
#define check_types_match(expr1, expr2)	\
	((typeof(expr1) *)0 != (typeof(expr2) *)0)
/**
 * ucontainer_of - get pointer to enclosing structure
 * @member_ptr: pointer to the structure member
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does pointer
 * subtraction to return the pointer to the enclosing type.
 *
 * Example:
 *	struct foo {
 *		int fielda, fieldb;
 *		// ...
 *	};
 *	struct info {
 *		int some_other_field;
 *		struct foo my_foo;
 *	};
 *
 *	static struct info *foo_to_info(struct foo *foo)
 *	{
 *		return ucontainer_of(foo, struct info, my_foo);
 *	}
 */
#define ucontainer_of(member_ptr, containing_type, member)		\
	 ((containing_type *)						\
	  ((char *)(member_ptr)						\
	   - ulist_container_off(containing_type, member))			\
	  + check_types_match(*(member_ptr), ((containing_type *)0)->member))
/**
 * ulist_container_off - get offset to enclosing structure
 * @containing_type: the type this member is within
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does
 * typechecking and figures out the offset to the enclosing type.
 *
 * Example:
 *	struct foo {
 *		int fielda, fieldb;
 *		// ...
 *	};
 *	struct info {
 *		int some_other_field;
 *		struct foo my_foo;
 *	};
 *
 *	static struct info *foo_to_info(struct foo *foo)
 *	{
 *		size_t off = ulist_container_off(struct info, my_foo);
 *		return (void *)((char *)foo - off);
 *	}
 */
#define ulist_container_off(containing_type, member)	\
	offsetof(containing_type, member)
/**
 * container_of_var - get pointer to enclosing structure using a variable
 * @member_ptr: pointer to the structure member
 * @container_var: a pointer of same type as this member's container
 * @member: the name of this member within the structure.
 *
 * Given a pointer to a member of a structure, this macro does pointer
 * subtraction to return the pointer to the enclosing type.
 *
 * Example:
 *	static struct info *foo_to_i(struct foo *foo)
 *	{
 *		struct info *i = container_of_var(foo, i, my_foo);
 *		return i;
 *	}
 */
#define container_of_var(member_ptr, container_var, member) \
	ucontainer_of(member_ptr, typeof(*container_var), member)
/**
 * ulist_container_off_var - get offset of a field in enclosing structure
 * @container_var: a pointer to a container structure
 * @member: the name of a member within the structure.
 *
 * Given (any) pointer to a structure and a its member name, this
 * macro does pointer subtraction to return offset of member in a
 * structure memory layout.
 *
 */
#define ulist_container_off_var(var, member)		\
	ulist_container_off(typeof(*var), member)
/**
 * struct ulist_node - an entry in a doubly-linked list
 * @next: next entry (self if empty)
 * @prev: previous entry (self if empty)
 *
 * This is used as an entry in a linked list.
 * Example:
 *	struct child {
 *		const char *name;
 *		// Linked list of all us children.
 *		struct ulist_node list;
 *	};
 */
    struct ulist_node {
	struct ulist_node *next, *prev;
};

/**
 * struct ulist_head - the head of a doubly-linked list
 * @h: the ulist_head (containing next and prev pointers)
 *
 * This is used as the head of a linked list.
 * Example:
 *	struct parent {
 *		const char *name;
 *		struct ulist_head children;
 *		unsigned int num_children;
 *	};
 */
struct ulist_head {
	struct ulist_node n;
};

/**
 * ulist_check - check head of a list for consistency
 * @h: the ulist_head
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Because ulist_nodes have redundant information, consistency checking between
 * the back and forward links can be done.  This is useful as a debugging check.
 * If @abortstr is non-NULL, that will be printed in a diagnostic if the list
 * is inconsistent, and the function will abort.
 *
 * Returns the list head if the list is consistent, NULL if not (it
 * can never return NULL if @abortstr is set).
 *
 * See also: ulist_check_node()
 *
 * Example:
 *	static void dump_parent(struct parent *p)
 *	{
 *		struct child *c;
 *
 *		printf("%s (%u children):\n", p->name, p->num_children);
 *		ulist_check(&p->children, "bad child list");
 *		ulist_for_each(&p->children, c, list)
 *			printf(" -> %s\n", c->name);
 *	}
 */
struct ulist_head *ulist_check(const struct ulist_head *h,
			       const char *abortstr);

/**
 * ulist_check_node - check node of a list for consistency
 * @n: the ulist_node
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Check consistency of the list node is in (it must be in one).
 *
 * See also: ulist_check()
 *
 * Example:
 *	static void dump_child(const struct child *c)
 *	{
 *		ulist_check_node(&c->list, "bad child list");
 *		printf("%s\n", c->name);
 *	}
 */
struct ulist_node *ulist_check_node(const struct ulist_node *n,
				    const char *abortstr);

#ifdef __ULIST_DEBUG_
#define ulist_debug(h) ulist_check((h), __func__)
#define ulist_debug_node(n) ulist_check_node((n), __func__)
#else
#define ulist_debug(h) (h)
#define ulist_debug_node(n) (n)
#endif

/**
 * ULIST_HEAD_INIT - initializer for an empty ulist_head
 * @name: the name of the list.
 *
 * Explicit initializer for an empty list.
 *
 * See also:
 *	ULIST_HEAD, ulist_head_init()
 *
 * Example:
 *	static struct ulist_head my_list = ULIST_HEAD_INIT(my_list);
 */
#define ULIST_HEAD_INIT(name) { { &name.n, &name.n } }

/**
 * ULIST_HEAD - define and initialize an empty ulist_head
 * @name: the name of the list.
 *
 * The ULIST_HEAD macro defines a ulist_head and initializes it to an empty
 * list.  It can be prepended by "static" to define a static ulist_head.
 *
 * See also:
 *	ULIST_HEAD_INIT, ulist_head_init()
 *
 * Example:
 *	static ULIST_HEAD(my_global_list);
 */
#define ULIST_HEAD(name) \
	struct ulist_head name = ULIST_HEAD_INIT(name)

/**
 * ulist_head_init - initialize a ulist_head
 * @h: the ulist_head to set to the empty list
 *
 * Example:
 *	...
 *	struct parent *parent = malloc(sizeof(*parent));
 *
 *	ulist_head_init(&parent->children);
 *	parent->num_children = 0;
 */
static inline void ulist_head_init(struct ulist_head *h)
{
	h->n.next = h->n.prev = &h->n;
}

/**
 * ulist_add - add an entry at the start of a linked list.
 * @h: the ulist_head to add the node to
 * @n: the ulist_node to add to the list.
 *
 * The ulist_node does not need to be initialized; it will be overwritten.
 * Example:
 *	struct child *child = malloc(sizeof(*child));
 *
 *	child->name = "marvin";
 *	ulist_add(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void ulist_add(struct ulist_head *h, struct ulist_node *n)
{
	n->next = h->n.next;
	n->prev = &h->n;
	h->n.next->prev = n;
	h->n.next = n;
	(void)ulist_debug(h);
}

/**
 * ulist_add_tail - add an entry at the end of a linked list.
 * @h: the ulist_head to add the node to
 * @n: the ulist_node to add to the list.
 *
 * The ulist_node does not need to be initialized; it will be overwritten.
 * Example:
 *	ulist_add_tail(&parent->children, &child->list);
 *	parent->num_children++;
 */
static inline void ulist_add_tail(struct ulist_head *h, struct ulist_node *n)
{
	n->next = &h->n;
	n->prev = h->n.prev;
	h->n.prev->next = n;
	h->n.prev = n;
	(void)ulist_debug(h);
}

/**
 * ulist_insert - insert an entry after another linked list node.
 * @h: the ulist_head to add the node to
 * @n: the ulist_node to add to the list.
 * @after: the ulist_node after which to add the new entry
 *
 * The ulist_node does not need to be initialized; it will be overwritten.
 * Example:
 *	ulist_insert(&parent->children, &child->list, &after_child->list);
 *	parent->num_children++;
 */
static inline void ulist_insert(struct ulist_head *h, struct ulist_node *n,
				struct ulist_node *after)
{
	n->next = after->next;
	n->prev = after;
	after->next = n;
	(void)ulist_debug(h);
}

/**
 * ulist_empty - is a list empty?
 * @h: the ulist_head
 *
 * If the list is empty, returns true.
 *
 * Example:
 *	assert(ulist_empty(&parent->children) == (parent->num_children == 0));
 */
static inline bool ulist_empty(const struct ulist_head *h)
{
	(void)ulist_debug(h);
	return h->n.next == &h->n;
}

/**
 * ulist_del - delete an entry from an (unknown) linked list.
 * @n: the ulist_node to delete from the list.
 *
 * Note that this leaves @n in an undefined state; it can be added to
 * another list, but not deleted again.
 *
 * See also:
 *	ulist_del_from()
 *
 * Example:
 *	ulist_del(&child->list);
 *	parent->num_children--;
 */
static inline void ulist_del(struct ulist_node *n)
{
	(void)ulist_debug_node(n);
	n->next->prev = n->prev;
	n->prev->next = n->next;
#ifdef __ULIST_DEBUG_
	/* Catch use-after-del. */
	n->next = n->prev = NULL;
#endif
}

/**
 * ulist_del_from - delete an entry from a known linked list.
 * @h: the ulist_head the node is in.
 * @n: the ulist_node to delete from the list.
 *
 * This explicitly indicates which list a node is expected to be in,
 * which is better documentation and can catch more bugs.
 *
 * See also: ulist_del()
 *
 * Example:
 *	ulist_del_from(&parent->children, &child->list);
 *	parent->num_children--;
 */
static inline void ulist_del_from(struct ulist_head *h, struct ulist_node *n)
{
#ifdef __ULIST_DEBUG_
	{
		/* Thorough check: make sure it was in list! */
		struct ulist_node *i;
		for (i = h->n.next; i != n; i = i->next)
			assert(i != &h->n);
	}
#endif				/* __ULIST_DEBUG_ */

	/* Quick test that catches a surprising number of bugs. */
	assert(!ulist_empty(h));
	ulist_del(n);
}

/**
 * ulist_entry - convert a ulist_node back into the structure containing it.
 * @n: the ulist_node
 * @type: the type of the entry
 * @member: the ulist_node member of the type
 *
 * Example:
 *	// First list entry is children.next; convert back to child.
 *	child = ulist_entry(parent->children.n.next, struct child, list);
 *
 * See Also:
 *	ulist_top(), ulist_for_each()
 */
#define ulist_entry(n, type, member) ucontainer_of(n, type, member)

/**
 * ulist_top - get the first entry in a list
 * @h: the ulist_head
 * @type: the type of the entry
 * @member: the ulist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *first;
 *	first = ulist_top(&parent->children, struct child, list);
 *	if (!first)
 *		printf("Empty list!\n");
 */
#define ulist_top(h, type, member)					\
	((type *)ulist_top_((h), ulist_off_(type, member)))

static inline const void *ulist_top_(const struct ulist_head *h, size_t off)
{
	if (ulist_empty(h))
		return NULL;
	return (const char *)h->n.next - off;
}

/**
 * ulist_pop - remove the first entry in a list
 * @h: the ulist_head
 * @type: the type of the entry
 * @member: the ulist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *one;
 *	one = ulist_pop(&parent->children, struct child, list);
 *	if (!one)
 *		printf("Empty list!\n");
 */
#define ulist_pop(h, type, member)					\
	((type *)ulist_pop_((h), ulist_off_(type, member)))

static inline const void *ulist_pop_(const struct ulist_head *h, size_t off)
{
	struct ulist_node *n;

	if (ulist_empty(h))
		return NULL;
	n = h->n.next;
	ulist_del(n);
	return (const char *)n - off;
}

/**
 * ulist_tail - get the last entry in a list
 * @h: the ulist_head
 * @type: the type of the entry
 * @member: the ulist_node member of the type
 *
 * If the list is empty, returns NULL.
 *
 * Example:
 *	struct child *last;
 *	last = ulist_tail(&parent->children, struct child, list);
 *	if (!last)
 *		printf("Empty list!\n");
 */
#define ulist_tail(h, type, member) \
	((type *)ulist_tail_((h), ulist_off_(type, member)))

static inline const void *ulist_tail_(const struct ulist_head *h, size_t off)
{
	if (ulist_empty(h))
		return NULL;
	return (const char *)h->n.prev - off;
}

/**
 * ulist_for_each - iterate through a list.
 * @h: the ulist_head (warning: evaluated multiple times!)
 * @i: the structure containing the ulist_node
 * @member: the ulist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	ulist_for_each(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define ulist_for_each(h, i, member)					\
	ulist_for_each_off(h, i, ulist_off_var_(i, member))

/**
 * ulist_for_each_rev - iterate through a list backwards.
 * @h: the ulist_head
 * @i: the structure containing the ulist_node
 * @member: the ulist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.
 *
 * Example:
 *	ulist_for_each_rev(&parent->children, child, list)
 *		printf("Name: %s\n", child->name);
 */
#define ulist_for_each_rev(h, i, member)					\
	for (i = container_of_var(ulist_debug(h)->n.prev, i, member);	\
	     &i->member != &(h)->n;					\
	     i = container_of_var(i->member.prev, i, member))

/**
 * ulist_for_each_safe - iterate through a list, maybe during deletion
 * @h: the ulist_head
 * @i: the structure containing the ulist_node
 * @nxt: the structure containing the ulist_node
 * @member: the ulist_node member of the structure
 *
 * This is a convenient wrapper to iterate @i over the entire list.  It's
 * a for loop, so you can break and continue as normal.  The extra variable
 * @nxt is used to hold the next element, so you can delete @i from the list.
 *
 * Example:
 *	struct child *next;
 *	ulist_for_each_safe(&parent->children, child, next, list) {
 *		ulist_del(&child->list);
 *		parent->num_children--;
 *	}
 */
#define ulist_for_each_safe(h, i, nxt, member)				\
	ulist_for_each_safe_off(h, i, nxt, ulist_off_var_(i, member))

/**
 * ulist_append_list - empty one list onto the end of another.
 * @to: the list to append into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the end of
 * @to.  After this @from will be empty.
 *
 * Example:
 *	struct ulist_head adopter;
 *
 *	ulist_append_list(&adopter, &parent->children);
 *	assert(ulist_empty(&parent->children));
 *	parent->num_children = 0;
 */
static inline void ulist_append_list(struct ulist_head *to,
				     struct ulist_head *from)
{
	struct ulist_node *from_tail = ulist_debug(from)->n.prev;
	struct ulist_node *to_tail = ulist_debug(to)->n.prev;

	/* Sew in head and entire list. */
	to->n.prev = from_tail;
	from_tail->next = &to->n;
	to_tail->next = &from->n;
	from->n.prev = to_tail;

	/* Now remove head. */
	ulist_del(&from->n);
	ulist_head_init(from);
}

/**
 * ulist_prepend_list - empty one list into the start of another.
 * @to: the list to prepend into
 * @from: the list to empty.
 *
 * This takes the entire contents of @from and moves it to the start
 * of @to.  After this @from will be empty.
 *
 * Example:
 *	ulist_prepend_list(&adopter, &parent->children);
 *	assert(ulist_empty(&parent->children));
 *	parent->num_children = 0;
 */
static inline void ulist_prepend_list(struct ulist_head *to,
				      struct ulist_head *from)
{
	struct ulist_node *from_tail = ulist_debug(from)->n.prev;
	struct ulist_node *to_head = ulist_debug(to)->n.next;

	/* Sew in head and entire list. */
	to->n.next = &from->n;
	from->n.prev = &to->n;
	to_head->prev = from_tail;
	from_tail->next = to_head;

	/* Now remove head. */
	ulist_del(&from->n);
	ulist_head_init(from);
}

/**
 * ulist_for_each_off - iterate through a list of memory regions.
 * @h: the ulist_head
 * @i: the pointer to a memory region wich contains list node data.
 * @off: offset(relative to @i) at which list node data resides.
 *
 * This is a low-level wrapper to iterate @i over the entire list, used to
 * implement all other, more high-level, for-each constructs.
 * It's a for loop, so you can break and continue as normal.
 *
 * WARNING! Being the low-level macro that it is, this wrapper doesn't know
 * nor care about the type of @i. The only assumtion made is that @i points
 * to a chunk of memory that at some @offset, relative to @i, contains a
 * properly filled `struct node_list' which in turn contains pointers to
 * memory chunks and it's turtles all the way down. Whith all that in mind
 * remember that given the wrong pointer/offset couple this macro will
 * happilly churn all you memory untill SEGFAULT stops it, in other words
 * caveat emptor.
 *
 * It is worth mentioning that one of legitimate use-cases for that wrapper
 * is operation on opaque types with known offset for `struct ulist_node'
 * member(preferably 0), because it allows you not to disclose the type of
 * @i.
 *
 * Example:
 *	ulist_for_each_off(&parent->children, child,
 *				offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define ulist_for_each_off(h, i, off)                                    \
  for (i = ulist_node_to_off_(ulist_debug(h)->n.next, (off));             \
       ulist_node_from_off_((void *)i, (off)) != &(h)->n;                \
       i = ulist_node_to_off_(ulist_node_from_off_((void *)i, (off))->next, \
                             (off)))

/**
 * ulist_for_each_safe_off - iterate through a list of memory regions, maybe
 * during deletion
 * @h: the ulist_head
 * @i: the pointer to a memory region wich contains list node data.
 * @nxt: the structure containing the ulist_node
 * @off: offset(relative to @i) at which list node data resides.
 *
 * For details see `ulist_for_each_off' and `ulist_for_each_safe'
 * descriptions.
 *
 * Example:
 *	ulist_for_each_safe_off(&parent->children, child,
 *		next, offsetof(struct child, list))
 *		printf("Name: %s\n", child->name);
 */
#define ulist_for_each_safe_off(h, i, nxt, off)                          \
  for (i = ulist_node_to_off_(ulist_debug(h)->n.next, (off)),             \
         nxt = ulist_node_to_off_(ulist_node_from_off_(i, (off))->next,   \
                                 (off));                                \
       ulist_node_from_off_(i, (off)) != &(h)->n;                        \
       i = nxt,                                                         \
         nxt = ulist_node_to_off_(ulist_node_from_off_(i, (off))->next,   \
                                 (off)))

/* Other -off variants. */
#define ulist_entry_off(n, type, off)		\
	((type *)ulist_node_from_off_((n), (off)))

#define ulist_head_off(h, type, off)		\
	((type *)ulist_head_off((h), (off)))

#define ulist_tail_off(h, type, off)		\
	((type *)ulist_tail_((h), (off)))

#define ulist_add_off(h, n, off)                 \
	ulist_add((h), ulist_node_from_off_((n), (off)))

#define ulist_del_off(n, off)                    \
	ulist_del(ulist_node_from_off_((n), (off)))

#define ulist_del_from_off(h, n, off)			\
	ulist_del_from(h, ulist_node_from_off_((n), (off)))

/* Offset helper functions so we only single-evaluate. */
static inline void *ulist_node_to_off_(struct ulist_node *node, size_t off)
{
	return (void *)((char *)node - off);
}

static inline struct ulist_node *ulist_node_from_off_(void *ptr, size_t off)
{
	return (struct ulist_node *)((char *)ptr + off);
}

/* Get the offset of the member, but make sure it's a ulist_node. */
#define ulist_off_(type, member)					\
	(ulist_container_off(type, member) +				\
	 check_type(((type *)0)->member, struct ulist_node))

#define ulist_off_var_(var, member)			\
	(ulist_container_off_var(var, member) +		\
	 check_type(var->member, struct ulist_node))

__END_DECLS
#endif				/* __LIST_H_ */
