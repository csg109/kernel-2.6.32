/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

#include <linux/module.h>
#include <net/tcp.h>

int sysctl_tcp_syn_retries __read_mostly = TCP_SYN_RETRIES;
int sysctl_tcp_synack_retries __read_mostly = TCP_SYNACK_RETRIES;
int sysctl_tcp_keepalive_time __read_mostly = TCP_KEEPALIVE_TIME;
int sysctl_tcp_keepalive_probes __read_mostly = TCP_KEEPALIVE_PROBES;
int sysctl_tcp_keepalive_intvl __read_mostly = TCP_KEEPALIVE_INTVL;
int sysctl_tcp_retries1 __read_mostly = TCP_RETR1;
int sysctl_tcp_retries2 __read_mostly = TCP_RETR2;
int sysctl_tcp_orphan_retries __read_mostly;
int sysctl_tcp_thin_linear_timeouts __read_mostly;

static void tcp_write_timer(unsigned long);
static void tcp_delack_timer(unsigned long);
static void tcp_keepalive_timer (unsigned long data);

void tcp_init_xmit_timers(struct sock *sk)
{
	inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer,
				  &tcp_keepalive_timer);
}

EXPORT_SYMBOL(tcp_init_xmit_timers);

static void tcp_write_err(struct sock *sk)
{
	sk->sk_err = sk->sk_err_soft ? : ETIMEDOUT;
	sk->sk_error_report(sk);

	tcp_done(sk);
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONTIMEOUT);
}

/* Do not allow orphaned sockets to eat all our resources.
 * This is direct violation of TCP specs, but it is required
 * to prevent DoS attacks. It is called when a retransmission timeout
 * or zero probe timeout occurs on orphaned socket.
 *
 * Criteria is still not confirmed experimentally and may change.
 * We kill the socket, if:
 * 1. If number of orphaned sockets exceeds an administratively configured
 *    limit.
 * 2. If we have strong memory pressure.
 */
static int tcp_out_of_resources(struct sock *sk, int do_reset)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int orphans = percpu_counter_read_positive(&tcp_orphan_count);

	/* If peer does not open window for long time, or did not transmit
	 * anything for long time, penalize it. */
	if ((s32)(tcp_time_stamp - tp->lsndtime) > 2*TCP_RTO_MAX || !do_reset)
		orphans <<= 1;

	/* If some dubious ICMP arrived, penalize even more. */
	if (sk->sk_err_soft)
		orphans <<= 1;

	if (tcp_too_many_orphans(sk, orphans)) {
		if (net_ratelimit())
			printk(KERN_INFO "Out of socket memory\n");

		/* Catch exceptional cases, when connection requires reset.
		 *      1. Last segment was sent recently. */
		if ((s32)(tcp_time_stamp - tp->lsndtime) <= TCP_TIMEWAIT_LEN ||
		    /*  2. Window is closed. */
		    (!tp->snd_wnd && !tp->packets_out))
			do_reset = 1;
		if (do_reset)
			tcp_send_active_reset(sk, GFP_ATOMIC);
		tcp_done(sk);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPABORTONMEMORY);
		return 1;
	}
	return 0;
}

/* Calculate maximal number or retries on an orphaned socket. */
static int tcp_orphan_retries(struct sock *sk, int alive)
{
	int retries = sysctl_tcp_orphan_retries; /* May be zero. */

	/* We know from an ICMP that something is wrong. */
	if (sk->sk_err_soft && !alive)
		retries = 0;

	/* However, if socket sent something recently, select some safe
	 * number of retries. 8 corresponds to >100 seconds with minimal
	 * RTO of 200msec. */
	if (retries == 0 && alive)
		retries = 8;
	return retries;
}

static void tcp_mtu_probing(struct inet_connection_sock *icsk, struct sock *sk)
{
	/* Black hole detection */
	if (sysctl_tcp_mtu_probing) {
		/* 如果mtu探测未开启(即sysctl_tcp_mtu_probing为1时只在路由黑洞时使用探测) */
		if (!icsk->icsk_mtup.enabled) {
			icsk->icsk_mtup.enabled = 1; /* 开启MTU探测 */
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		} else {
			struct tcp_sock *tp = tcp_sk(sk);
			int mss;

			mss = tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low) >> 1; /* mss减一半 */
			mss = min(sysctl_tcp_base_mss, mss); /* 且最大512 */
			mss = max(mss, 68 - tp->tcp_header_len); /* 且最小48 */
			icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss); /* 设置下限 */
			tcp_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
	}
}

/* A write timeout has occurred. Process the after effects. */
static int tcp_write_timeout(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int retry_until;
	bool do_reset, syn_set = 0;

	if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		if (icsk->icsk_retransmits)
			dst_negative_advice(&sk->sk_dst_cache);
		retry_until = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		syn_set = 1;
	} else {
		/* 超过sysctl_tcp_retries1次数后需要探测下mtu */
		if (retransmits_timed_out(sk, sysctl_tcp_retries1, 0)) {
			/* Black hole detection */
			tcp_mtu_probing(icsk, sk);

			dst_negative_advice(&sk->sk_dst_cache);
		}

		retry_until = sysctl_tcp_retries2;
		if (sock_flag(sk, SOCK_DEAD)) {
			const int alive = (icsk->icsk_rto < TCP_RTO_MAX);

			retry_until = tcp_orphan_retries(sk, alive);
			do_reset = alive ||
				   !retransmits_timed_out(sk, retry_until, 0);

			if (tcp_out_of_resources(sk, do_reset))
				return 1;
		}
	}

	/* 超过retry_until次数则放弃该连接 */
	if (retransmits_timed_out(sk, retry_until, syn_set)) {
		/* Has it gone just too far? */
		tcp_write_err(sk);
		return 1;
	}
	return 0;
}

/* delay-ack定时器处理函数 */
static void tcp_delack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		/* 如果延迟确认定时器触发时，发现用户进程正在使用此socket，就把blocked置为1。 
		 * 之后在接收到新数据、或者将数据复制到用户空间之后，会马上发送ACK
		 */
		icsk->icsk_ack.blocked = 1;
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		sk_reset_timer(sk, &icsk->icsk_delack_timer, jiffies + TCP_DELACK_MIN);
		goto out_unlock;
	}

	sk_mem_reclaim_partial(sk);

	/* 如果连接已关闭，或者延迟确认定时器并没有被启动，直接返回 */
	if (sk->sk_state == TCP_CLOSE || !(icsk->icsk_ack.pending & ICSK_ACK_TIMER))
		goto out;

	/* 如果还没有到超时时刻，则继续计时，直接返回 */
	if (time_after(icsk->icsk_ack.timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
		goto out;
	}
	icsk->icsk_ack.pending &= ~ICSK_ACK_TIMER; /* 去除延迟定时器的运行标志 */

	/* 如果prequeue队列不为空，则处理其中的数据包 */
	if (!skb_queue_empty(&tp->ucopy.prequeue)) {
		struct sk_buff *skb;

		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSCHEDULERFAILED);

		/* 从prequeue队列中取出skb，并从队列中删除 */
		while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
			sk_backlog_rcv(sk, skb); /* 调用tcp_v4_do_rcv()来处理 */

		tp->ucopy.memory = 0; /* 清零prequeue队列消耗的内存 */
	}

	/* 如果有ACK需要发送 */
	if (inet_csk_ack_scheduled(sk)) {
		/* 在快速确认模式中，如果分配skb失败，就无法发送ACK。 
		 * 此时也会启动延迟确认定时器，超时时间设为200ms。 
		 * 在这种情况下，如果再次发送失败，就要进行指数退避了
		 */
		if (!icsk->icsk_ack.pingpong) {
			/* Delayed ACK missed: inflate ATO. */
			icsk->icsk_ack.ato = min(icsk->icsk_ack.ato << 1, icsk->icsk_rto); /* 超时时间的指数退避 */
		} else { /* 如果是处于延迟确认模式 */
			/* Delayed ACK missed: leave pingpong mode and
			 * deflate ATO.
			 */
			icsk->icsk_ack.pingpong = 0; /* 切换到快速模式 */
			icsk->icsk_ack.ato      = TCP_ATO_MIN; /* 重置ATO */
		}
		tcp_send_ack(sk); /* 发送ACK */
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_DELAYEDACKS);
	}
	TCP_CHECK_TIMER(sk);

out:
	if (tcp_memory_pressure)
		sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/* 0窗口定时器处理函数 */
static void tcp_probe_timer(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int max_probes;

	if (tp->packets_out || !tcp_send_head(sk)) { /* 有数据包在网络上就不用探测了 */
		icsk->icsk_probes_out = 0;
		return;
	}

	/* *WARNING* RFC 1122 forbids this
	 *
	 * It doesn't AFAIK, because we kill the retransmit timer -AK
	 *
	 * FIXME: We ought not to do it, Solaris 2.5 actually has fixing
	 * this behaviour in Solaris down as a bug fix. [AC]
	 *
	 * Let me to explain. icsk_probes_out is zeroed by incoming ACKs
	 * even if they advertise zero window. Hence, connection is killed only
	 * if we received no ACKs for normal connection timeout. It is not killed
	 * only because window stays zero for some time, window may be zero
	 * until armageddon and even later. We are in full accordance
	 * with RFCs, only probe timer combines both retransmission timeout
	 * and probe timeout in one bottle.				--ANK
	 */
	max_probes = sysctl_tcp_retries2;

	if (sock_flag(sk, SOCK_DEAD)) { /* 处理连接已经断开，套接口即将关闭的情况 */
		const int alive = ((icsk->icsk_rto << icsk->icsk_backoff) < TCP_RTO_MAX);

		max_probes = tcp_orphan_retries(sk, alive);

		/* 释放资源，如果该套接口在释放过程中被关闭，则无需再发送探测了 */
		if (tcp_out_of_resources(sk, alive || icsk->icsk_probes_out <= max_probes))
			return;
	}

	if (icsk->icsk_probes_out > max_probes) { /* 连续探测超过15次且没收到ack则断开连接, icsk_probes_out会在tcp_ack中清零 */
		tcp_write_err(sk);
	} else {
		/* Only send another probe if we didn't close things up. */
		tcp_send_probe0(sk); /* 发送探测 */
	}
}

/*
 *	The TCP retransmit timer.
 */

void tcp_retransmit_timer(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* 如果没有需要确认的段，则什么也不做 */
	if (!tp->packets_out)
		goto out;

	WARN_ON(tcp_write_queue_empty(sk));

	/* 如果接收端的窗口为0, 则直接进入RTO
	 * 其中:  
	 * snd_wnd为窗口大小。  
	 * sock_flag用来判断sock的状态。  
	 * 最后一个判断是当前的连接状态不能处于syn_sent和syn_recv状态,也就是连接还未建立状态.
	 */
	if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
	    !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
		/* Receiver dastardly shrinks window. Our retransmits
		 * become zero probes, but we should not timeout this
		 * connection. If the socket is an orphan, time it out,
		 * we cannot allow such beasts to hang infinitely.
		 */
#ifdef TCP_DEBUG
		struct inet_sock *inet = inet_sk(sk);
		if (sk->sk_family == AF_INET) {
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI4:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &inet->daddr, ntohs(inet->dport),
			       inet->num, tp->snd_una, tp->snd_nxt);
		}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		else if (sk->sk_family == AF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			LIMIT_NETDEBUG(KERN_DEBUG "TCP: Peer %pI6:%u/%u unexpectedly shrunk window %u:%u (repaired)\n",
			       &np->daddr, ntohs(inet->dport),
			       inet->num, tp->snd_una, tp->snd_nxt);
		}
#endif
#endif
		/* 如果上一个收到的ACK已经过了TCP_RTO_MAX，则关闭这个连接 */
		if (tcp_time_stamp - tp->rcv_tstamp > TCP_RTO_MAX) {
			tcp_write_err(sk);
			goto out;
		}
		tcp_enter_loss(sk, 0); /* 进入loss状态 */
		tcp_retransmit_skb(sk, tcp_write_queue_head(sk)); /* 重传第一个未确认的包 */
		__sk_dst_reset(sk);
		goto out_reset_timer; /* 然后重启定时器，继续等待ack的到来 */
	}

	/* 判断重传需要的次数。如果超过了重传次数，直接跳转到out */
	if (tcp_write_timeout(sk))
		goto out;

	/* 到达这里说明我们重传的次数还没到。icsk->icsk_retransmits表示重传的次数 */
	if (icsk->icsk_retransmits == 0) {
		int mib_idx;

		if (icsk->icsk_ca_state == TCP_CA_Disorder) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKFAILURES;
			else
				mib_idx = LINUX_MIB_TCPRENOFAILURES;
		} else if (icsk->icsk_ca_state == TCP_CA_Recovery) {
			if (tcp_is_sack(tp))
				mib_idx = LINUX_MIB_TCPSACKRECOVERYFAIL;
			else
				mib_idx = LINUX_MIB_TCPRENORECOVERYFAIL;
		} else if (icsk->icsk_ca_state == TCP_CA_Loss) {
			mib_idx = LINUX_MIB_TCPLOSSFAILURES;
		} else {
			mib_idx = LINUX_MIB_TCPTIMEOUTS;
		}
		NET_INC_STATS_BH(sock_net(sk), mib_idx);
	}

	/* 是否使用f-rto算法 */
	if (tcp_use_frto(sk)) {
		tcp_enter_frto(sk); /* 使用F-RTO算法处理 */
	} else {
		tcp_enter_loss(sk, 0); /* 按照传统的RTO处理 */
	}

	/* 尝试重传队列的第一个段 */
	if (tcp_retransmit_skb(sk, tcp_write_queue_head(sk)) > 0) {
		/* Retransmission failed because of local congestion,
		 * do not backoff.
		 */
		if (!icsk->icsk_retransmits)
			icsk->icsk_retransmits = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  min(icsk->icsk_rto, TCP_RESOURCE_PROBE_INTERVAL),
					  TCP_RTO_MAX);
		goto out;
	}

	/* Increase the timeout each time we retransmit.  Note that
	 * we do not increase the rtt estimate.  rto is initialized
	 * from rtt, but increases here.  Jacobson (SIGCOMM 88) suggests
	 * that doubling rto each time is the least we can get away with.
	 * In KA9Q, Karn uses this for the first few times, and then
	 * goes to quadratic.  netBSD doubles, but only goes up to *64,
	 * and clamps at 1 to 64 sec afterwards.  Note that 120 sec is
	 * defined in the protocol as the maximum possible RTT.  I guess
	 * we'll have to use something other than TCP to talk to the
	 * University of Mars.
	 *
	 * PAWS allows us longer timeouts and large windows, so once
	 * implemented ftp to mars will work nicely. We will have to fix
	 * the 120 second clamps though!
	 */
	icsk->icsk_backoff++; /* icsk->icsk_backoff主要用在零窗口定时器 */
	icsk->icsk_retransmits++; /* icsk_retransmits也就是重试次数 */

out_reset_timer:
	/* If stream is thin, use linear timeouts. Since 'icsk_backoff' is
	 * used to reset timer, set to 0. Recalculate 'icsk_rto' as this
	 * might be increased if the stream oscillates between thin and thick,
	 * thus the old value might already be too high compared to the value
	 * set by 'tcp_set_rto' in tcp_input.c which resets the rto without
	 * backoff. Limit to TCP_THIN_LINEAR_RETRIES before initiating
	 * exponential backoff behaviour to avoid continue hammering
	 * linear-timeout retransmissions into a black hole
	 */
	if (sk->sk_state == TCP_ESTABLISHED &&
	    (tp->thin_lto || sysctl_tcp_thin_linear_timeouts) &&
	    tcp_stream_is_thin(tp) &&
	    icsk->icsk_retransmits <= TCP_THIN_LINEAR_RETRIES) {
		icsk->icsk_backoff = 0;
		icsk->icsk_rto = min(__tcp_set_rto(tp), TCP_RTO_MAX);
	} else {
		/* Use normal (exponential) backoff */
		/* 计算rto，并重启定时器，这里使用karn算法，也就是下次超时时间增加一倍 */
		icsk->icsk_rto = min(icsk->icsk_rto << 1, TCP_RTO_MAX);
	}
	/* 重启定时器，超时时间就是上面的icsk_rto */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS, icsk->icsk_rto, TCP_RTO_MAX);
	/* 超过sysctl_tcp_retries1+1次数重置路由缓存 */
	if (retransmits_timed_out(sk, sysctl_tcp_retries1 + 1, 0)) 
		__sk_dst_reset(sk);

out:;
}

static void tcp_write_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	int event;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later */
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, jiffies + (HZ / 20));
		goto out_unlock;
	}

	/* 如果状态为close或者icsk_pending为空，则什么也不做 */
	if (sk->sk_state == TCP_CLOSE || !icsk->icsk_pending)
		goto out;

	/* 如果超时时间已经过了，则重启定时器 */
	if (time_after(icsk->icsk_timeout, jiffies)) {
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
		goto out;
	}

	event = icsk->icsk_pending; /* 取出定时器类型 */
	icsk->icsk_pending = 0;

	/* 通过判断event来确定进入那个函数进行处理 */
	switch (event) {
	case ICSK_TIME_RETRANS:
		tcp_retransmit_timer(sk); /* 重传定时器 */
		break;
	case ICSK_TIME_PROBE0:
		tcp_probe_timer(sk); /* 0窗口定时器 */
		break;
	}
	TCP_CHECK_TIMER(sk);

out:
	sk_mem_reclaim(sk);
out_unlock:
	bh_unlock_sock(sk);
	sock_put(sk);
}

/*
 *	Timer for listening sockets
 */

static void tcp_synack_timer(struct sock *sk)
{
	inet_csk_reqsk_queue_prune(sk, TCP_SYNQ_INTERVAL,
				   TCP_TIMEOUT_INIT, TCP_RTO_MAX);
}

void tcp_set_keepalive(struct sock *sk, int val)
{
	/* 不在以下两个状态设置保活定时器： 
	 * TCP_CLOSE：sk_timer用作FIN_WAIT2定时器 
	 * TCP_LISTEN：sk_timer用作SYNACK重传定时器
	 */
	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	/* 如果SO_KEEPALIVE选项值为1，且此前没有设置SOCK_KEEPOPEN标志， 
	 * 则激活sk_timer，用作保活定时器
	 */
	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		inet_csk_reset_keepalive_timer(sk, keepalive_time_when(tcp_sk(sk)));
	else if (!val) /* 如果SO_KEEPALIVE选项值为0，则删除保活定时器 */
		inet_csk_delete_keepalive_timer(sk);
}


static void tcp_keepalive_timer (unsigned long data)
{
	struct sock *sk = (struct sock *) data;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 elapsed;

	/* Only process if socket is not in use. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Try again later. */
		inet_csk_reset_keepalive_timer (sk, HZ/20);
		goto out;
	}

	/* listen状态则执行syn-ack定时器 */
	if (sk->sk_state == TCP_LISTEN) { 
		tcp_synack_timer(sk);
		goto out;
	}

	/* FIN_WAIT2定时器 */
	if (sk->sk_state == TCP_FIN_WAIT2 && sock_flag(sk, SOCK_DEAD)) {
		if (tp->linger2 >= 0) {
			const int tmo = tcp_fin_time(sk) - TCP_TIMEWAIT_LEN;

			/* tmo > 0 说明是之前tcp_fin_time() > TCP_TIMEWAIT_LEN的情况，
			 * 继续等待tmo的FIN_WAIT2超时
			 */
			if (tmo > 0) {
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
		tcp_send_active_reset(sk, GFP_ATOMIC); /* 发送RST */
		goto death; /* 释放sock */
	}

	/* 以下为Keepalive保活定时器 */
	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_CLOSE)
		goto out;

	elapsed = keepalive_time_when(tp); /* 连接的空闲时间超过此值，就发送保活探测报文 */

	/* It is alive without keepalive 8) */
	/* 如果网络中有发送且未确认的数据包，或者发送队列不为空，说明连接不是idle的
	 * 既然连接不是idle的，就没有必要探测对端是否正常。 
	 * 保活定时器重新开始计时即可。 
	 */
	if (tp->packets_out || tcp_send_head(sk))
		goto resched; /* 重置keepalive定时器 */

	elapsed = keepalive_time_elapsed(tp); /* 连接经历的空闲时间，即上次收到报文至今的时间 */

	if (elapsed >= keepalive_time_when(tp)) { /* 如果连接空闲的时间超过了设置的时间值 */
		/* 发送的保活探测包达到了保活探测的最大次数, 发送RST然后断开连接 */
		if (icsk->icsk_probes_out >= keepalive_probes(tp)) {
			tcp_send_active_reset(sk, GFP_ATOMIC);
			tcp_write_err(sk);
			goto out;
		}
		/* 如果还不到关闭连接的时候，就继续发送保活探测包 */
		if (tcp_write_wakeup(sk) <= 0) { /* 这里发送探测包 */
			icsk->icsk_probes_out++; /* 已发送的保活探测包个数 */
			elapsed = keepalive_intvl_when(tp); /* 下次超时的时间，默认为75s */
		} else {
			/* If keepalive was lost due to local congestion,
			 * try harder.
			 */
			elapsed = TCP_RESOURCE_PROBE_INTERVAL; /* 默认为500ms，会使超时更加频繁 */
		}
	} else {
		/* It is tp->rcv_tstamp + keepalive_time_when(tp) */
		/* 如果连接的空闲时间，还没有超过设定值，则接着等待 */
		elapsed = keepalive_time_when(tp) - elapsed;
	}

	TCP_CHECK_TIMER(sk);
	sk_mem_reclaim(sk);

resched:
	inet_csk_reset_keepalive_timer (sk, elapsed);
	goto out;

death:
	tcp_done(sk);

out:
	bh_unlock_sock(sk);
	sock_put(sk);
}
