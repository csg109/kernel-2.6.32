/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Generic INET transport hashtables
 *
 * Authors:	Lotsa people, from code originally in tcp
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/secure_seq.h>
#include <net/ip.h>

/*
 * Allocate and initialize a new local port bind bucket.
 * The bindhash mutex for snum's hash chain must be held here.
 */
struct inet_bind_bucket *inet_bind_bucket_create(struct kmem_cache *cachep,
						 struct net *net,
						 struct inet_bind_hashbucket *head,
						 const unsigned short snum)
{
	struct inet_bind_bucket *tb = kmem_cache_alloc(cachep, GFP_ATOMIC);

	if (tb != NULL) {
		write_pnet(&tb->ib_net, hold_net(net));
		tb->port      = snum;
		tb->fastreuse = 0;
		tb->num_owners = 0;
		INIT_HLIST_HEAD(&tb->owners);
		hlist_add_head(&tb->node, &head->chain);
	}
	return tb;
}

/*
 * Caller must hold hashbucket lock for this tb with local BH disabled
 */
void inet_bind_bucket_destroy(struct kmem_cache *cachep, struct inet_bind_bucket *tb)
{
	if (hlist_empty(&tb->owners)) {
		__hlist_del(&tb->node);
		release_net(ib_net(tb));
		kmem_cache_free(cachep, tb);
	}
}

void inet_bind_hash(struct sock *sk, struct inet_bind_bucket *tb,
		    const unsigned short snum)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;

	atomic_inc(&hashinfo->bsockets);

	inet_sk(sk)->num = snum;
	sk_add_bind_node(sk, &tb->owners);
	tb->num_owners++;
	inet_csk(sk)->icsk_bind_hash = tb;
}

/*
 * Get rid of any references to a local port held by the given sock.
 */
static void __inet_put_port(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	const int bhash = inet_bhashfn(sock_net(sk), inet_sk(sk)->num,
			hashinfo->bhash_size);
	struct inet_bind_hashbucket *head = &hashinfo->bhash[bhash];
	struct inet_bind_bucket *tb;

	atomic_dec(&hashinfo->bsockets);

	spin_lock(&head->lock);
	tb = inet_csk(sk)->icsk_bind_hash;
	__sk_del_bind_node(sk);
	tb->num_owners--;
	inet_csk(sk)->icsk_bind_hash = NULL;
	inet_sk(sk)->num = 0;
	inet_bind_bucket_destroy(hashinfo->bind_bucket_cachep, tb);
	spin_unlock(&head->lock);
}

void inet_put_port(struct sock *sk)
{
	local_bh_disable();
	__inet_put_port(sk);
	local_bh_enable();
}

EXPORT_SYMBOL(inet_put_port);

int __inet_inherit_port(struct sock *sk, struct sock *child)
{
	struct inet_hashinfo *table = sk->sk_prot->h.hashinfo;
	unsigned short port = inet_sk(child)->num;
	const int bhash = inet_bhashfn(sock_net(sk), port,
			table->bhash_size);
	struct inet_bind_hashbucket *head = &table->bhash[bhash];
	struct inet_bind_bucket *tb;

	spin_lock(&head->lock);
	tb = inet_csk(sk)->icsk_bind_hash;
	if (tb->port != port) {
		/* NOTE: using tproxy and redirecting skbs to a proxy
		 * on a different listener port breaks the assumption
		 * that the listener socket's icsk_bind_hash is the same
		 * as that of the child socket. We have to look up or
		 * create a new bind bucket for the child here. */
		struct hlist_node *node;
		inet_bind_bucket_for_each(tb, node, &head->chain) {
			if (net_eq(ib_net(tb), sock_net(sk)) &&
			    tb->port == port)
				break;
		}
		if (!node) {
			tb = inet_bind_bucket_create(table->bind_bucket_cachep,
						     sock_net(sk), head, port);
			if (!tb) {
				spin_unlock(&head->lock);
				return -ENOMEM;
			}
		}
	}
	sk_add_bind_node(child, &tb->owners);
	inet_csk(child)->icsk_bind_hash = tb;
	spin_unlock(&head->lock);

	return 0;
}

EXPORT_SYMBOL_GPL(__inet_inherit_port);

static inline int compute_score(struct sock *sk, struct net *net,
				const unsigned short hnum, const __be32 daddr,
				const int dif)
{
	int score = -1;
	struct inet_sock *inet = inet_sk(sk);

	/* 同属一个NET 本地端口匹配 且不是纯ipv6 */
	if (net_eq(sock_net(sk), net) && inet->num == hnum &&
			!ipv6_only_sock(sk)) {
		__be32 rcv_saddr = inet->rcv_saddr;
		/* 协议一致得1分, 即ipv4的数据包会优先选择ipv4的sock */
		score = sk->sk_family == PF_INET ? 1 : 0; 
		if (rcv_saddr) { /* 本地绑定地址匹配，加2分 */
			if (rcv_saddr != daddr)
				return -1;
			score += 2;
		}
		if (sk->sk_bound_dev_if) { /* 网卡匹配，加2分 */
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score += 2;
		}
	}
	return score;
}

/*
 * Don't inline this cruft. Here are some nice properties to exploit here. The
 * BSD API does not allow a listening sock to specify the remote port nor the
 * remote address for the connection. So always assume those are both
 * wildcarded during the search since they can never be otherwise.
 */


struct sock *__inet_lookup_listener(struct net *net,
				    struct inet_hashinfo *hashinfo,
				    const __be32 daddr, const unsigned short hnum,
				    const int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned int hash = inet_lhashfn(net, hnum);
	struct inet_listen_hashbucket *ilb = &hashinfo->listening_hash[hash];
	int score, hiscore;

	rcu_read_lock();
begin:
	result = NULL;
	hiscore = -1;
	sk_nulls_for_each_rcu(sk, node, &ilb->head) {
		/* 遍历这个桶内所有监听sk，选择一个最匹配的（分值最高的） */
		score = compute_score(sk, net, hnum, daddr, dif);
		if (score > hiscore) {
			result = sk;
			hiscore = score;
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != hash + LISTENING_NULLS_BASE)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero(&result->sk_refcnt)))
			result = NULL;
		else if (unlikely(compute_score(result, net, hnum, daddr,
				  dif) < hiscore)) {
			sock_put(result);
			goto begin;
		}
	}
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(__inet_lookup_listener);

struct sock * __inet_lookup_established(struct net *net,
				  struct inet_hashinfo *hashinfo,
				  const __be32 saddr, const __be16 sport,
				  const __be32 daddr, const u16 hnum,
				  const int dif)
{
	INET_ADDR_COOKIE(acookie, saddr, daddr)
	const __portpair ports = INET_COMBINED_PORTS(sport, hnum);
	struct sock *sk;
	const struct hlist_nulls_node *node;
	/* Optimize here for direct hit, only listening connections can
	 * have wildcards anyways.
	 */
	unsigned int hash = inet_ehashfn(net, daddr, hnum, saddr, sport); /* 计算哈希值 */
	unsigned int slot = hash & (hashinfo->ehash_size - 1); /* 计算桶索引 */
	struct inet_ehash_bucket *head = &hashinfo->ehash[slot]; /* 获取established的哈希链表 */

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(sk, node, &head->chain) { /* 遍历established链表 */
		if (INET_MATCH(sk, net, hash, acookie,
					saddr, daddr, ports, dif)) { /* 匹配各种相同 */
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt)))
				goto begintw; /* 去找time_wait */
			if (unlikely(!INET_MATCH(sk, net, hash, acookie,
				saddr, daddr, ports, dif))) { /* 再验证一遍 */
				sock_put(sk);
				goto begin;
			}
			goto out; /* 找到了 */
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begin;

begintw:
	/* Must check for a TIME_WAIT'er before going to listener hash. */
	sk_nulls_for_each_rcu(sk, node, &head->twchain) { /* 遍历time_wait链表 */
		if (INET_TW_MATCH(sk, net, hash, acookie,
					saddr, daddr, ports, dif)) {
			if (unlikely(!atomic_inc_not_zero(&sk->sk_refcnt))) {
				sk = NULL;
				goto out;
			}
			if (unlikely(!INET_TW_MATCH(sk, net, hash, acookie,
				 saddr, daddr, ports, dif))) {
				sock_put(sk);
				goto begintw;
			}
			goto out; /* 找到time_wait */
		}
	}
	/*
	 * if the nulls value we got at the end of this lookup is
	 * not the expected one, we must restart lookup.
	 * We probably met an item that was moved to another chain.
	 */
	if (get_nulls_value(node) != slot)
		goto begintw;
	sk = NULL;
out:
	rcu_read_unlock();
	return sk;
}
EXPORT_SYMBOL_GPL(__inet_lookup_established);

/* called with local bh disabled */
/* 判断正在使用中的端口是否允许重用 */
static int __inet_check_established(struct inet_timewait_death_row *death_row,
				    struct sock *sk, __u16 lport,
				    struct inet_timewait_sock **twp)
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	struct inet_sock *inet = inet_sk(sk);
	__be32 daddr = inet->rcv_saddr;
	__be32 saddr = inet->daddr;
	int dif = sk->sk_bound_dev_if;
	INET_ADDR_COOKIE(acookie, saddr, daddr) /* 根据目的IP和源IP，生成一个64位的值 */
	const __portpair ports = INET_COMBINED_PORTS(inet->dport, lport); /* 根据目的端口和源端口，生成一个32位的值 */
	struct net *net = sock_net(sk);
	unsigned int hash = inet_ehashfn(net, daddr, lport, saddr, inet->dport); /* 通过连接的四元组，计算得到一个哈希值 */
	struct inet_ehash_bucket *head = inet_ehash_bucket(hinfo, hash); /* 根据计算得到的哈希值，从哈希表中找到对应的哈希桶 */
	spinlock_t *lock = inet_ehash_lockp(hinfo, hash); /* 根据计算得到的哈希值，从哈希表中找到对应哈希桶的锁 */
	struct sock *sk2;
	const struct hlist_nulls_node *node;
	struct inet_timewait_sock *tw;

	spin_lock(lock); /* 锁住哈希桶 */

	/* Check TIME-WAIT sockets first. */
	/* 先查找time_wait哈希桶 */
	sk_nulls_for_each(sk2, node, &head->twchain) {
		tw = inet_twsk(sk2);

		/* 如果连接完全匹配：四元组相同、绑定的设备相同 */
		if (INET_TW_MATCH(sk2, net, hash, acookie,
					saddr, daddr, ports, dif)) {
			/* 四元组一样，满足以下条件就允许复用：
			 * 1. 使用TCP Timestamp选项
			 * 2. 符合以下任一情况即可：
			 *   2.1 twp == NULL，主动建立连接时，如果用户已经绑定端口了，那么会符合
			 *   2.2 启用tcp_tw_reuse，且距离上次收到数据包的时间大于1s
			 */
			if (twsk_unique(sk, sk2, twp))
				goto unique; /* 可以复用 */
			else
				goto not_unique; /* 不允许复用 */
		}
	}
	tw = NULL;

	/* And established part... */
	/* 再查找established哈希桶 */
	sk_nulls_for_each(sk2, node, &head->chain) {
		/* 如果连接完全匹配：四元组相同、绑定的设备相同 */
		if (INET_MATCH(sk2, net, hash, acookie,
					saddr, daddr, ports, dif))
			goto not_unique; /* 有相同的四元组，不能复用 */
	}

unique:
	/* 走到这里有两种情况
	 * 1. 遍历玩哈希桶，都没有找到四元组一样的。 
	 * 2. 找到了四元组一样的，但是符合重用的条件。
	 */

	/* Must record num and sport now. Otherwise we will see
	 * in hash table socket with a funny identity. */
	inet->num = lport; /* 保存源端口 */
	inet->sport = htons(lport); /* 网络序的源端口 */
	sk->sk_hash = hash; /* 保存ehash表的哈希值 */
	WARN_ON(!sk_unhashed(sk)); /* 要求新连接sk还没被链入ehash哈希表中 */
	__sk_nulls_add_node_rcu(sk, &head->chain); /* 把此sk链入ehash哈希表中 */
	spin_unlock(lock);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

	/* 如果twp不为NULL，各种哈希表删除操作，就交给调用函数来处理 */
	if (twp) {
		*twp = tw;
		NET_INC_STATS_BH(net, LINUX_MIB_TIMEWAITRECYCLED);
	} else if (tw) {
		/* Silly. Should hash-dance instead... */
		inet_twsk_deschedule(tw, death_row); /* 把tw从death_row、ehash、bhash的哈希表中删除，更新tw的引用计数 */
		NET_INC_STATS_BH(net, LINUX_MIB_TIMEWAITRECYCLED);

		inet_twsk_put(tw); /* 释放tw结构体 */
	}

	return 0;

not_unique:
	spin_unlock(lock);
	return -EADDRNOTAVAIL;
}

/* 根据源IP、目的IP、目的端口，采用MD5计算出一个随机数，作为端口的初始偏移值 */
static inline u32 inet_sk_port_offset(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	return secure_ipv4_port_ephemeral(inet->rcv_saddr, inet->daddr,
					  inet->dport);
}

/* 将创建的sock插入到established哈希表中 */
void __inet_hash_nolisten(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo; /* 取得tcp_hashinfo */
	struct hlist_nulls_head *list;
	spinlock_t *lock;
	struct inet_ehash_bucket *head;

	WARN_ON(!sk_unhashed(sk));

	sk->sk_hash = inet_sk_ehashfn(sk); /* 根据四元组计算哈希值 */
	head = inet_ehash_bucket(hashinfo, sk->sk_hash); /* 根据哈希值取得哈希桶链表 */
	list = &head->chain; /* 获取存放eatablished状态的哈希链表 */
	lock = inet_ehash_lockp(hashinfo, sk->sk_hash); /* 获取哈希链表的锁 */

	spin_lock(lock); /* 修改上锁 */
	__sk_nulls_add_node_rcu(sk, list); /* 插入rcu的表中 */
	spin_unlock(lock);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
}
EXPORT_SYMBOL_GPL(__inet_hash_nolisten);

static void __inet_hash(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_listen_hashbucket *ilb;

	if (sk->sk_state != TCP_LISTEN) {
		__inet_hash_nolisten(sk);
		return;
	}

	WARN_ON(!sk_unhashed(sk));
	ilb = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)];

	spin_lock(&ilb->lock);
	__sk_nulls_add_node_rcu(sk, &ilb->head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	spin_unlock(&ilb->lock);
}

void inet_hash(struct sock *sk)
{
	if (sk->sk_state != TCP_CLOSE) {
		local_bh_disable();
		__inet_hash(sk);
		local_bh_enable();
	}
}
EXPORT_SYMBOL_GPL(inet_hash);

void inet_unhash(struct sock *sk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo; /* 获取tcp_hashinfo */
	spinlock_t *lock;
	int done;

	if (sk_unhashed(sk)) /* 如果已经不在表中则直接返回 */
		return;

	if (sk->sk_state == TCP_LISTEN)
		lock = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)].lock;
	else
		lock = inet_ehash_lockp(hashinfo, sk->sk_hash); /* 获取锁 */

	spin_lock_bh(lock);
	done =__sk_nulls_del_node_init_rcu(sk); /* 从表中删除 */
	if (done)
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	spin_unlock_bh(lock);
}
EXPORT_SYMBOL_GPL(inet_unhash);

int __inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk, u32 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **),
		void (*hash)(struct sock *sk))
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	const unsigned short snum = inet_sk(sk)->num; /* 本端端口 */
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *tb;
	int ret;
	struct net *net = sock_net(sk);

	if (!snum) { /* snum为0时，表示用户没有绑定端口，默认让系统自动选取端口 */
		int i, remaining, low, high, port;
		static u32 hint; /* 用于保存上次查找的位置 */
		u32 offset = hint + port_offset;
		struct hlist_node *node;
		struct inet_timewait_sock *tw = NULL;

		/* 系统自动分配时，获取端口号的取值范围 */
		inet_get_local_port_range(&low, &high);
		remaining = (high - low) + 1; /* 取值范围内端口号的个数 */

		local_bh_disable();
		for (i = 1; i <= remaining; i++) {
			/* 根据MD5计算得到的port_offset值，以及hint，获取范围内的一个端口 */
			port = low + (i + offset) % remaining;
			/* 如果此端口号属于保留的，那么直接跳过 */
			if (inet_is_reserved_local_port(port))
				continue;
			/* 根据端口号，找到所在的哈希桶 */
			head = &hinfo->bhash[inet_bhashfn(net, port,
					hinfo->bhash_size)];
			spin_lock(&head->lock); /* 锁住此哈希桶 */

			/* Does not bother with rcv_saddr checks,
			 * because the established check is already
			 * unique enough.
			 */
			/* 从头遍历哈希桶 */
			inet_bind_bucket_for_each(tb, node, &head->chain) {
				/* 如果此端口已经被使用了 */
				if (ib_net(tb) == net && tb->port == port) {
					/* 不允许使用已经被bind()绑定的端口，无论此端口是否能够被复用 */
					if (tb->fastreuse >= 0)
						goto next_port;
					WARN_ON(hlist_empty(&tb->owners));
					/* 检查端口是否允许重用 */
					if (!check_established(death_row, sk,
								port, &tw))
						goto ok; /* 成功，该端口可以被重复使用 */
					goto next_port; /* 失败，下一个端口 */
				}
			}

			/* 走到这里，表示该端口尚未被使用
			 * 创建一个inet_bind_bucket实例，并把它加入到哈希桶中
			 */
			tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
					net, head, port);
			/* 如果内存不够，则退出端口选择, 会导致connect()失败，返回-EADDRNOTAVAIL */
			if (!tb) {
				spin_unlock(&head->lock);
				break;
			}
			tb->fastreuse = -1;
			goto ok;

		next_port:
			spin_unlock(&head->lock);
		}
		local_bh_enable();

		/* 有两种可能：内存不够、端口区间内的端口号用光 */
		return -EADDRNOTAVAIL;

ok:
		hint += i; /* 下一次connect()时，查找端口增加了这段偏移 */

		/* Head lock still held and bh's disabled */
		/* 把tb赋值给icsk->icsk_bind_hash，更新inet->inet_num，
		 * 把sock链入tb->owners哈希链中, 
		 * 更新该端口的绑定次数，系统总的端口绑定次数 
		 */
		inet_bind_hash(sk, tb, port);
		/* 如果sk尚未链入ehash哈希表中 */
		if (sk_unhashed(sk)) {
			inet_sk(sk)->sport = htons(port); /* 保存本地端口 */
			hash(sk); /* 调用__inet_hash_nolisten把sk链入到ehash哈希表中，把tw从ehash表中删除 */
		}
		spin_unlock(&head->lock);

		if (tw) {
			/* 把tw从tcp_death_row、ehash、bhash的哈希表中删除，更新tw的引用计数 */
			inet_twsk_deschedule(tw, death_row);
			inet_twsk_put(tw); /* 释放tw结构体 */
		}

		ret = 0;
		goto out;
	}

	/* 走到这里，表示用户已经自己绑定了端口 */
	head = &hinfo->bhash[inet_bhashfn(net, snum, hinfo->bhash_size)]; /* 端口所在的哈希桶 */
	tb  = inet_csk(sk)->icsk_bind_hash; /* 端口的存储实例 */
	spin_lock_bh(&head->lock);
	/* 如果sk是此端口的使用者队列的第一个节点 */
	if (sk_head(&tb->owners) == sk && !sk->sk_bind_node.next) {
		hash(sk); /* 计算sk在ehash中的索引，赋值给sk->sk_hash，把sk链入到ehash表中 */
		spin_unlock_bh(&head->lock);
		return 0;
	} else {
		spin_unlock(&head->lock);
		/* No definite answer... Walk to established hash table */
		ret = check_established(death_row, sk, snum, NULL); /*  查看是否有可以重用的端口 */
out:
		local_bh_enable();
		return ret;
	}
}

/*
 * Bind a port for a connect operation and hash it.
 */
int inet_hash_connect(struct inet_timewait_death_row *death_row,
		      struct sock *sk)
{
	return __inet_hash_connect(death_row, sk, inet_sk_port_offset(sk),
			__inet_check_established, __inet_hash_nolisten);
}

EXPORT_SYMBOL_GPL(inet_hash_connect);

void inet_hashinfo_init(struct inet_hashinfo *h)
{
	int i;

	atomic_set(&h->bsockets, 0);
	for (i = 0; i < INET_LHTABLE_SIZE; i++) {
		spin_lock_init(&h->listening_hash[i].lock);
		INIT_HLIST_NULLS_HEAD(&h->listening_hash[i].head,
				      i + LISTENING_NULLS_BASE);
		}
}

EXPORT_SYMBOL_GPL(inet_hashinfo_init);
