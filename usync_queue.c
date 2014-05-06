/*
 * File: usync_queue.c
 * Summary: synchronized queue based on double linked list and
 *          pthreads synchronization primitives
 *
 * Author: Alexander Nezhinsky (nezhinsky@gmail.com)
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
#include <pthread.h>
#include <sched.h>

#include "ulist.h"
#include "usync_queue.h"

#ifdef	__cplusplus
extern "C" {
#endif

void usync_queue_init(struct usync_queue *q)
{
	pthread_mutex_init(&q->qlist_mutex, NULL);
	pthread_cond_init(&q->qlist_cond, NULL);
	ulist_head_init(&q->qlist);
	ulist_head_init(&q->accum_list);
	q->active = 1;
}

inline void usync_queue_push_list_(struct usync_queue *q,
	struct ulist_head *h)
{
	pthread_mutex_lock(&q->qlist_mutex);
	ulist_append_list(&q->qlist, h);
	pthread_cond_signal(&q->qlist_cond);
	pthread_mutex_unlock(&q->qlist_mutex);
}

void usync_queue_accum(struct usync_queue *q, struct ulist_node *n)
{
	ulist_add_tail(&q->accum_list, n);
}

void usync_queue_push_accum(struct usync_queue *q)
{
	usync_queue_push_list_(q, &q->accum_list);
}

void usync_queue_push_list(struct usync_queue *q,
	struct ulist_head *h)
{
	usync_queue_push_list_(q, h);
}

void usync_queue_push_node(struct usync_queue *q, struct ulist_node *n)
{
	pthread_mutex_lock(&q->qlist_mutex);
	ulist_add_tail(&q->qlist, n);
	pthread_cond_signal(&q->qlist_cond);
	pthread_mutex_unlock(&q->qlist_mutex);
}

struct ulist_node *usync_queue_pop_(struct usync_queue *q, size_t off)
{
	struct ulist_node *n;

	pthread_mutex_lock(&q->qlist_mutex);
	if (q->active) {
		while (ulist_empty(&q->qlist))
			pthread_cond_wait(&q->qlist_cond, &q->qlist_mutex);
		n = (struct ulist_node *)ulist_pop_(&q->qlist, off);
	} else
		n = NULL;
	pthread_mutex_unlock(&q->qlist_mutex);

	return n;
}

int usync_queue_pull_list(struct usync_queue *q, struct ulist_head *h)
{
	int err = 0;

	pthread_mutex_lock(&q->qlist_mutex);
	if (q->active) {
		while (ulist_empty(&q->qlist))
			pthread_cond_wait(&q->qlist_cond, &q->qlist_mutex);
		ulist_append_list(h, &q->qlist); /* move qlist to h */
	} else
		err = -1;
	pthread_mutex_unlock(&q->qlist_mutex);

	return err;
}

void usync_queue_shutdown(struct usync_queue *q)
{
	pthread_mutex_lock(&q->qlist_mutex);
	while (!ulist_empty(&q->qlist)) {
		pthread_mutex_unlock(&q->qlist_mutex);
		sched_yield();
		pthread_mutex_lock(&q->qlist_mutex);
	}
	q->active = 0;
	pthread_cond_signal(&q->qlist_cond);
	pthread_mutex_unlock(&q->qlist_mutex);
}



#ifdef	__cplusplus
}
#endif

