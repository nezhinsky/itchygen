/*
 * File:   usync_queue.h
 */

#ifndef __USYNC_QUEUE_H_
#define	__USYNC_QUEUE_H_

#include <pthread.h>

#include "ulist.h"

#ifdef	__cplusplus
extern "C" {
#endif

struct usync_queue {
	pthread_mutex_t qlist_mutex;
	pthread_cond_t qlist_cond;
	struct ulist_head qlist;
	struct ulist_head accum_list;
	int active;
};

void usync_queue_init(struct usync_queue *q);

void usync_queue_accum(struct usync_queue *q, struct ulist_node *n);
void usync_queue_push_accum(struct usync_queue *q);

void usync_queue_push_list(struct usync_queue *q, struct ulist_head *h);

void usync_queue_push_node(struct usync_queue *q, struct ulist_node *n);

struct ulist_node *usync_queue_pop_(struct usync_queue *q, size_t off);

#define usync_queue_pop(q, type, member) \
	(usync_queue_pop_(q, ulist_off_(type, member)))

void usync_queue_pull_list(struct usync_queue *q, struct ulist_head *h);

void usync_queue_shutdown(struct usync_queue *q);

#ifdef	__cplusplus
}
#endif

#endif	/* __USYNC_QUEUE_H_ */

