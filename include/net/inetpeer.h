/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

/* inet_peer保存了与当前主机通信的主机(对端)的一些信息 */
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	struct inet_peer	*avl_left, *avl_right;
						/* avl树的左子树和右子树 */
	__be32			v4daddr;	/* peer's address */
						/* 远端peer的ip地址  */
	__u16			avl_height;	/* 树的高度 */
	__u16			ip_id_count;	/* IP ID for the next packet */
						/* 下一个使用这个peer的包id(
						 * ip数据包id的选择,就是基于这个域,
						 * 也就是每次通过传入ip地址,得到当前应使用的id(inet_getid())
						 */
	struct list_head	unused;		/* 这个链表包含了所有定时器到期的peer
						 * 由于peer初始化的时候内存大小有限制,
						 * 因此我们就需要定时将在给定时间内没有使用的peer放到这个链表中,
						 * 只有当它的引用计数为0时,才会最终从unused中移除 
						 */
	__u32			dtime;		/* the time of last use of not
						 * referenced entries */
						/* 被加入到unused链表中(通过inet_putpeer)的jiffies时间 */
	atomic_t		refcnt;		/* 引用计数 */
	atomic_t		rid;		/* Frag reception counter */
						/* 帧结束的计数器 */
	__u32			tcp_ts;		/* TCP用来记录上一次收到对端的时间戳, 用于tcp_tw_recycle */
	unsigned long		tcp_ts_stamp;	/* TCP用来记录上一次收到对端时间戳的时间, 用于tcp_tw_recycle */
};

void			inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(__be32 daddr, int create);

/* can be called from BH context or outside */
extern void inet_putpeer(struct inet_peer *p);

extern spinlock_t inet_peer_idlock;
/* can be called with or without local BH being disabled */
static inline __u16	inet_getid(struct inet_peer *p, int more)
{
	__u16 id;

	spin_lock_bh(&inet_peer_idlock);
	id = p->ip_id_count;
	p->ip_id_count += 1 + more;
	spin_unlock_bh(&inet_peer_idlock);
	return id;
}

#endif /* _NET_INETPEER_H */
