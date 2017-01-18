/*
 * NET		Generic infrastructure for Network protocols.
 *
 *		Definitions for request_sock 
 *
 * Authors:	Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 *
 * 		From code originally in include/net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _REQUEST_SOCK_H
#define _REQUEST_SOCK_H

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/bug.h>

#include <net/sock.h>

struct request_sock;
struct sk_buff;
struct dst_entry;
struct proto;

struct request_sock_ops {
	int		family;		/* 所属的协议族 */
	int		obj_size; 	/* 连接请求块的大小 */
	struct kmem_cache	*slab;	/* 连接请求块的高速缓存 */
	char		*slab_name;
	int		(*rtx_syn_ack)(struct sock *sk,
				       struct request_sock *req); /* 重传SYNACK */
	void		(*send_ack)(struct sock *sk, struct sk_buff *skb,
				    struct request_sock *req);	/* 发送ACK */
	void		(*send_reset)(struct sock *sk,
				      struct sk_buff *skb); 	/* 发送RST */
	void		(*destructor)(struct request_sock *req); /* 析构函数 */
};

/* struct request_sock - mini sock to represent a connection request
 */
struct request_sock {
	struct request_sock		*dl_next; /* Must be first member! */
	u16				mss;	 /* 客户端通告的MSS */
	u8				retrans; /* 重传SYN-ACK的次数 */
	u8				cookie_ts; /* syncookie: encode tcpopts in timestamp */
						/* 置位表示 使用syncooke时如果开启timestamp则把TCP选项携带在timestamp中 */
	/* The following two fields can be easily recomputed I think -AK */
	u32				window_clamp; /* window clamp at creation time */
						      /* 本端的最大通告窗口 */
	u32				rcv_wnd;	  /* rcv_wnd offered first time */
							  /* 本端的接收窗口大小 */
	u32				ts_recent;	  /* 下个发送段的时间戳回显值 */
	unsigned long			expires;	  /* SYN-ACK的超时时间 */
	const struct request_sock_ops	*rsk_ops;	  /* 指向tcp_request_sock_ops，操作函数 */
	struct sock			*sk;		  /* 连接建立之前无效 */
	u32				secid;
	u32				peer_secid;
};

static inline struct request_sock *reqsk_alloc(const struct request_sock_ops *ops)
{
	struct request_sock *req = kmem_cache_alloc(ops->slab, GFP_ATOMIC);

	if (req != NULL)
		req->rsk_ops = ops;

	return req;
}

static inline void __reqsk_free(struct request_sock *req)
{
	kmem_cache_free(req->rsk_ops->slab, req);
}

static inline void reqsk_free(struct request_sock *req)
{
	req->rsk_ops->destructor(req);
	__reqsk_free(req);
}

extern int sysctl_max_syn_backlog;

/** struct listen_sock - listen state
 *
 * @max_qlen_log - log_2 of maximal queued SYNs/REQUESTs
 */
struct listen_sock {
	u8			max_qlen_log; 	/* qlen最大长度取对数log，即log2 (max_qlen)，
						 * 函数reqsk_queue_is_full()用来判断半连接数是否超过最大值 
						 */
	/* 3 bytes hole, try to use */
	int			qlen;		/* 当前的半连接队列中请求块的数据 */
	int			qlen_young;	/* 当前未重传过SYN-ACK的请求块的数目 */
	int			clock_hand;	/* 每次SYN-ACK定时器超时时，我们需要遍历SYN队列哈希表，
						 * 但表太大了，所以每次都只遍历部分哈希表，
						 * 而每次遍历完，将哈希索引值放在clock_hand这里，
						 * 下次遍历时直接从clock_hand开始，而不用从头开始 
						 */
	u32			hash_rnd;	/* 用来计算syn_table哈希表中哈希值的随机数 */
	u32			nr_table_entries; /* syn_table哈希表中桶的个数 */
	struct request_sock	*syn_table[0];	/* 半连接队列的哈希表
						 * SYN请求会新建一个request_sock结构,
						 * 并将它加入到listen_sock的syn_table哈希表中.
						 * 然后等到收到握手最后的ACK时，
						 * 将request_sock从syn_table哈希表中删除，
						 * 加入到request_sock_queue的rskq_accept_head和rskq_accept_tail队列中，
						 *
						 * 最后accept()系统调用判断accept队列是否存在完成3次请求的request_sock，
						 * 从这个队列中将request_sock结构释放
						 */
};

/** struct request_sock_queue - queue of request_socks
 *
 * @rskq_accept_head - FIFO head of established children
 * @rskq_accept_tail - FIFO tail of established children
 * @rskq_defer_accept - User waits for some data after accept()
 * @syn_wait_lock - serializer
 *
 * %syn_wait_lock is necessary only to avoid proc interface having to grab the main
 * lock sock while browsing the listening hash (otherwise it's deadlock prone).
 *
 * This lock is acquired in read mode only from listening_get_next() seq_file
 * op and it's acquired in write mode _only_ from code that is actively
 * changing rskq_accept_head. All readers that are holding the master sock lock
 * don't need to grab this lock in read mode too as rskq_accept_head. writes
 * are always protected from the main sock lock.
 */
struct request_sock_queue {
	struct request_sock	*rskq_accept_head; /* 已完成握手的队列，等待应用层accept() */
	struct request_sock	*rskq_accept_tail; /* rskq_accept_head的尾部 */
	rwlock_t		syn_wait_lock; 	   /* 操作listen_opt(syn_table哈希表)的读写锁 */
	u8			rskq_defer_accept; /* 应用层设置，用来在收到真正的数据包之后才建立连接，
						    * 而不是收到握手中的ACK建立连接，防止全连接攻击 
						    */
	/* 3 bytes hole, try to pack */
	struct listen_sock	*listen_opt;	   /* 用于半连接队列，包括半连接的哈希表 */
};

extern int reqsk_queue_alloc(struct request_sock_queue *queue,
			     unsigned int nr_table_entries);

extern void __reqsk_queue_destroy(struct request_sock_queue *queue);
extern void reqsk_queue_destroy(struct request_sock_queue *queue);

static inline struct request_sock *
	reqsk_queue_yank_acceptq(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	queue->rskq_accept_head = NULL;
	return req;
}

static inline int reqsk_queue_empty(struct request_sock_queue *queue)
{
	return queue->rskq_accept_head == NULL;
}

static inline void reqsk_queue_unlink(struct request_sock_queue *queue,
				      struct request_sock *req,
				      struct request_sock **prev_req)
{
	write_lock(&queue->syn_wait_lock);
	*prev_req = req->dl_next;
	write_unlock(&queue->syn_wait_lock);
}

static inline void reqsk_queue_add(struct request_sock_queue *queue,
				   struct request_sock *req,
				   struct sock *parent,
				   struct sock *child)
{
	req->sk = child;
	sk_acceptq_added(parent);

	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_head = req;
	else
		queue->rskq_accept_tail->dl_next = req;

	queue->rskq_accept_tail = req;
	req->dl_next = NULL;
}

static inline struct request_sock *reqsk_queue_remove(struct request_sock_queue *queue)
{
	struct request_sock *req = queue->rskq_accept_head;

	WARN_ON(req == NULL);

	queue->rskq_accept_head = req->dl_next;
	if (queue->rskq_accept_head == NULL)
		queue->rskq_accept_tail = NULL;

	return req;
}

static inline struct sock *reqsk_queue_get_child(struct request_sock_queue *queue,
						 struct sock *parent)
{
	struct request_sock *req = reqsk_queue_remove(queue); /* 获取第一个请求块 */
	struct sock *child = req->sk;

	WARN_ON(child == NULL);

	sk_acceptq_removed(parent);
	__reqsk_free(req);
	return child;
}

static inline int reqsk_queue_removed(struct request_sock_queue *queue,
				      struct request_sock *req)
{
	struct listen_sock *lopt = queue->listen_opt;

	if (req->retrans == 0)
		--lopt->qlen_young;

	return --lopt->qlen;
}

static inline int reqsk_queue_added(struct request_sock_queue *queue)
{
	struct listen_sock *lopt = queue->listen_opt;
	const int prev_qlen = lopt->qlen; /* 之前的半连接队列长度 */

	lopt->qlen_young++;	/* 更新未重传过的请求块数 */
	lopt->qlen++;		/* 更新半连接队列长度 */
	return prev_qlen;
}

static inline int reqsk_queue_len(const struct request_sock_queue *queue)
{
	return queue->listen_opt != NULL ? queue->listen_opt->qlen : 0;
}

static inline int reqsk_queue_len_young(const struct request_sock_queue *queue)
{
	return queue->listen_opt->qlen_young;
}

static inline int reqsk_queue_is_full(const struct request_sock_queue *queue)
{
	/* max_qlen_log为log2(max(qlen))，
	 * 如果qlen>>max_qlen_log不等于0的话，则表示qlen超出了最大连接的个数 
	 */
	return queue->listen_opt->qlen >> queue->listen_opt->max_qlen_log;
}

static inline void reqsk_queue_hash_req(struct request_sock_queue *queue,
					u32 hash, struct request_sock *req,
					unsigned long timeout)
{
	struct listen_sock *lopt = queue->listen_opt;

	req->expires = jiffies + timeout;	/* SYNACK的超时时间 */
	req->retrans = 0;			/* SYNACK的重传次数 */
	req->sk = NULL;				/* 连接尚未建立 */
	req->dl_next = lopt->syn_table[hash];	/* 指向下一个req */

	write_lock(&queue->syn_wait_lock);
	lopt->syn_table[hash] = req;		/* 把请求链入半连接队列 */
	write_unlock(&queue->syn_wait_lock);
}

#endif /* _REQUEST_SOCK_H */
