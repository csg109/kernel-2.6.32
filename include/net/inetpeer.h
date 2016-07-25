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

/* inet_peer�������뵱ǰ����ͨ�ŵ�����(�Զ�)��һЩ��Ϣ */
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	struct inet_peer	*avl_left, *avl_right;
						/* avl������������������ */
	__be32			v4daddr;	/* peer's address */
						/* Զ��peer��ip��ַ  */
	__u16			avl_height;	/* ���ĸ߶� */
	__u16			ip_id_count;	/* IP ID for the next packet */
						/* ��һ��ʹ�����peer�İ�id(
						 * ip���ݰ�id��ѡ��,���ǻ��������,
						 * Ҳ����ÿ��ͨ������ip��ַ,�õ���ǰӦʹ�õ�id(inet_getid())
						 */
	struct list_head	unused;		/* ���������������ж�ʱ�����ڵ�peer
						 * ����peer��ʼ����ʱ���ڴ��С������,
						 * ������Ǿ���Ҫ��ʱ���ڸ���ʱ����û��ʹ�õ�peer�ŵ����������,
						 * ֻ�е��������ü���Ϊ0ʱ,�Ż����մ�unused���Ƴ� 
						 */
	__u32			dtime;		/* the time of last use of not
						 * referenced entries */
						/* �����뵽unused������(ͨ��inet_putpeer)��jiffiesʱ�� */
	atomic_t		refcnt;		/* ���ü��� */
	atomic_t		rid;		/* Frag reception counter */
						/* ֡�����ļ����� */
	__u32			tcp_ts;		/* TCP������¼��һ���յ��Զ˵�ʱ���, ����tcp_tw_recycle */
	unsigned long		tcp_ts_stamp;	/* TCP������¼��һ���յ��Զ�ʱ�����ʱ��, ����tcp_tw_recycle */
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
