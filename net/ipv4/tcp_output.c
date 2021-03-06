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

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#include <net/tcp.h>

#include <linux/compiler.h>
#include <linux/module.h>

/* People can turn this off for buggy TCP's found in printers etc. */
int sysctl_tcp_retrans_collapse __read_mostly = 1;

/* People can turn this on to work with those rare, broken TCPs that
 * interpret the window field as a signed quantity.
 */
int sysctl_tcp_workaround_signed_windows __read_mostly = 0;

/* This limits the percentage of the congestion window which we
 * will allow a single TSO frame to consume.  Building TSO frames
 * which are too large can cause TCP streams to be bursty.
 */
int sysctl_tcp_tso_win_divisor __read_mostly = 3;

int sysctl_tcp_mtu_probing __read_mostly = 0;
int sysctl_tcp_base_mss __read_mostly = 512;

/* By default, RFC2861 behavior.  */
int sysctl_tcp_slow_start_after_idle __read_mostly = 1;

/* Account for new data that has been sent to the network. */
static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

	tcp_advance_send_head(sk, skb); 	/* 更新sk_send_head */
	tp->snd_nxt = TCP_SKB_CB(skb)->end_seq; /* 更新snd_nxt */

	/* Don't override Nagle indefinately with F-RTO */
	if (tp->frto_counter == 2)
		tp->frto_counter = 3;

	tp->packets_out += tcp_skb_pcount(skb);
	if (!prior_packets)
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
}

/* SND.NXT, if window was not shrunk.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!before(tcp_wnd_end(tp), tp->snd_nxt))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst && dst_metric(dst, RTAX_ADVMSS) < mss) {
		mss = dst_metric(dst, RTAX_ADVMSS);
		tp->advmss = mss;
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism. */
static void tcp_cwnd_restart(struct sock *sk, struct dst_entry *dst)
{
	struct tcp_sock *tp = tcp_sk(sk);
	s32 delta = tcp_time_stamp - tp->lsndtime;
	u32 restart_cwnd = tcp_init_cwnd(tp, dst);
	u32 cwnd = tp->snd_cwnd;

	tcp_ca_event(sk, CA_EVENT_CWND_RESTART); /* 触发拥塞窗口重置事件 */

	tp->snd_ssthresh = tcp_current_ssthresh(sk); /* 阈值保存下来，并没有重置 */
	restart_cwnd = min(restart_cwnd, cwnd);

	/* 闲置时间每超过一个RTO且cwnd比重置后的大时，cwnd减半 */
	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd); /* 取其大者 */
	tp->snd_cwnd_stamp = tcp_time_stamp;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
/* tcp_event_data_sent()中，符合三个条件才重置cwnd：
 * （1）tcp_slow_start_after_idle选项设置，这个内核默认置为1
 * （2）tp->packets_out == 0，表示网络中没有未确认数据包
 * （3）now - tp->lsndtime > icsk->icsk_rto，距离上次发送数据包的时间超过了RTO
 */
static void tcp_event_data_sent(struct tcp_sock *tp,
				struct sk_buff *skb, struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_time_stamp;

	if (sysctl_tcp_slow_start_after_idle &&
	    (!tp->packets_out && (s32)(now - tp->lsndtime) > icsk->icsk_rto))
		tcp_cwnd_restart(sk, __sk_dst_get(sk)); /* 重置cnwd  */

	tp->lsndtime = now; /* 更新最近发包的时间 */

	/* If it is a reply for ato after last received
	 * packet, enter pingpong mode.
	 */
	/* 如果此时距离最近接收到数据包的时间间隔足够短，
	 * 说明双方处于你来我往的双向数据传输中，
	 * 就进入延迟确认模式
	 * 即如果距离上次接收到数据包的时间在ato内，则进入延迟确认模式
	 */

	if ((u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		icsk->icsk_ack.pingpong = 1;
}

/* Account for an ACK we sent. */
static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts)
{
	tcp_dec_quickack_mode(sk, pkts); /* 更新快速确认模式的ACK额度 */
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK); /* 删除ACK延迟定时器, 并清零icsk->icsk_ack.pending */
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (65535 << 14); /* 设置为最大接收窗口 */
	space = min(*window_clamp, space); /* 不能超过window_clamp */

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = (space / mss) * mss; /* 对齐到MSS */

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sysctl_tcp_workaround_signed_windows) /* 一般关闭 */
		/* 不能超过32767，因为一些奇葩协议采用有符号的接收窗口大小 */
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = space; /* 设置初始接收窗口 */

	(*rcv_wscale) = 0;
	/* 这里计算wscale的值：
	 * 取tcp_rmem[2]和rmem_max的大者来计算需要多大的wscale才能表示
	 */
	if (wscale_ok) {
		/* Set window scaling on max possible window
		 * See RFC1323 for an explanation of the limit to 14
		 */
		space = max_t(u32, sysctl_tcp_rmem[2], sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		while (space > 65535 && (*rcv_wscale) < 14) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}

	/* Set initial window to a value enough for senders starting with
	 * initial congestion window of TCP_DEFAULT_INIT_RCVWND. Place
	 * a limit on the initial window when mss is larger than 1460.
	 */
	/* 这里限制了初始的接收窗口为10个MSS */
	if (mss > (1 << *rcv_wscale)) {
		int init_cwnd = TCP_DEFAULT_INIT_RCVWND;
		/* 如果MSS太大，为了防止初始接收窗口太大，所以需要调整下 */
		if (mss > 1460)
			init_cwnd =
			max_t(u32, (1460 * TCP_DEFAULT_INIT_RCVWND) / mss, 2);

		*rcv_wnd = min(*rcv_wnd, init_cwnd * mss);
	}

	/* Set the clamp no higher than max representable value */
	/* 设置window_clamp为最大能表示的接收窗口的值 */
	(*window_clamp) = min(65535U << (*rcv_wscale), *window_clamp);
}

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cur_win = tcp_receive_window(tp); /* 当前接收窗口的剩余大小 */
	u32 new_win = __tcp_select_window(sk);/* 根据剩余的接收缓存，计算新的接收窗口的大小 */

	/* Never shrink the offered window */
	/* 不允许缩小已分配的接收窗口 */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win; /* 更新接收窗口大小 */
	tp->rcv_wup = tp->rcv_nxt; /* 更新接收窗口的左边界，把未确认的数据累积确认 */

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	/* 确保接收窗口大小不超过规定的最大值 */
	if (!tp->rx_opt.rcv_wscale && sysctl_tcp_workaround_signed_windows)
		/* 不能超过32767，因为一些奇葩协议采用有符号的接收窗口大小 */
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale; /* 按比例因子缩小接收窗口，这样最多能表示30位 */

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0)
		tp->pred_flags = 0;

	return new_win; /* 返回最终的接收窗口大小 */
}

/* Packet ECN state for a SYN-ACK */
static inline void TCP_ECN_send_synack(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_ECE;
}

/* Packet ECN state for a SYN.  */
static inline void TCP_ECN_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->ecn_flags = 0;
	if (sysctl_tcp_ecn == 1) {
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_ECE | TCPCB_FLAG_CWR;
		tp->ecn_flags = TCP_ECN_OK;
	}
}

static __inline__ void
TCP_ECN_make_synack(struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
static inline void TCP_ECN_send(struct sock *sk, struct sk_buff *skb,
				int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				tcp_hdr(skb)->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			tcp_hdr(skb)->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->csum = 0;

	TCP_SKB_CB(skb)->flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPCB_FLAG_SYN | TCPCB_FLAG_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

static inline int tcp_urg_mode(const struct tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)

struct tcp_out_options {
	u8 options;		/* bit field of OPTION_* */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u16 mss;		/* 0 to disable */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
};

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operatibility perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			      const struct tcp_out_options *opts,
			      __u8 **md5_hash) {
	if (unlikely(OPTION_MD5 & opts->options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) |
			       TCPOLEN_MD5SIG);
		*md5_hash = (__u8 *)ptr;
		ptr += 4;
	} else {
		*md5_hash = NULL;
	}

	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}

	if (likely(OPTION_TS & opts->options)) {
		if (unlikely(OPTION_SACK_ADVERTISE & opts->options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}

	if (unlikely(OPTION_SACK_ADVERTISE & opts->options &&
		     !(OPTION_TS & opts->options))) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	}

	if (unlikely(OPTION_WSCALE & opts->options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}

	if (unlikely(opts->num_sack_blocks)) {
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
			tp->duplicate_sack : tp->selective_acks;
		int this_sack;

		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
						     TCPOLEN_SACK_PERBLOCK)));

		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}

		tp->rx_opt.dsack = 0;
	}
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				struct tcp_out_options *opts,
				struct tcp_md5sig_key **md5) {
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned size = 0;

#ifdef CONFIG_TCP_MD5SIG
	*md5 = tp->af_specific->md5_lookup(sk, sk);
	if (*md5) {
		opts->options |= OPTION_MD5;
		size += TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	size += TCPOLEN_MSS_ALIGNED;

	if (likely(sysctl_tcp_timestamps && *md5 == NULL)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		size += TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			size += TCPOLEN_SACKPERM_ALIGNED;
	}

	return size;
}

/* Set up TCP options for SYN-ACKs. */
static unsigned tcp_synack_options(struct sock *sk,
				   struct request_sock *req,
				   unsigned mss, struct sk_buff *skb,
				   struct tcp_out_options *opts,
				   struct tcp_md5sig_key **md5) {
	unsigned size = 0;
	struct inet_request_sock *ireq = inet_rsk(req);
	char doing_ts;

#ifdef CONFIG_TCP_MD5SIG
	*md5 = tcp_rsk(req)->af_specific->md5_lookup(sk, req);
	if (*md5) {
		opts->options |= OPTION_MD5;
		size += TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif

	/* we can't fit any SACK blocks in a packet with MD5 + TS
	   options. There was discussion about disabling SACK rather than TS in
	   order to fit in better with old, buggy kernels, but that was deemed
	   to be unnecessary. */
	doing_ts = ireq->tstamp_ok && !(*md5 && ireq->sack_ok);

	opts->mss = mss;
	size += TCPOLEN_MSS_ALIGNED;

	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		size += TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(doing_ts)) {
		opts->options |= OPTION_TS;
		opts->tsval = TCP_SKB_CB(skb)->when;
		opts->tsecr = req->ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!doing_ts))
			size += TCPOLEN_SACKPERM_ALIGNED;
	}

	return size;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
static unsigned tcp_established_options(struct sock *sk, struct sk_buff *skb,
					struct tcp_out_options *opts,
					struct tcp_md5sig_key **md5) {
	struct tcp_skb_cb *tcb = skb ? TCP_SKB_CB(skb) : NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned size = 0;
	unsigned int eff_sacks;

#ifdef CONFIG_TCP_MD5SIG
	*md5 = tp->af_specific->md5_lookup(sk, sk);
	if (unlikely(*md5)) {
		opts->options |= OPTION_MD5;
		size += TCPOLEN_MD5SIG_ALIGNED;
	}
#else
	*md5 = NULL;
#endif

	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcb ? tcb->when : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}

	eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
	if (unlikely(eff_sacks)) {
		const unsigned remaining = MAX_TCP_OPTION_SPACE - size;
		opts->num_sack_blocks =
			min_t(unsigned, eff_sacks,
			      (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
			      TCPOLEN_SACK_PERBLOCK);
		size += TCPOLEN_SACK_BASE_ALIGNED +
			opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
	}

	return size;
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned tcp_options_size, tcp_header_size;
	struct tcp_md5sig_key *md5;
	__u8 *md5_hash_location;
	struct tcphdr *th;
	int err;

	BUG_ON(!skb || !tcp_skb_pcount(skb));

	/* If congestion control is doing timestamping, we must
	 * take such a timestamp before we potentially clone/copy.
	 */
	/* 如果拥塞控制需要做时间采样，则必须在克隆或者拷贝报文之前设置一个时间戳。
	 * linux支持了多达十种拥塞控制算法，但并不是每种算中都需要做时间采样的，
	 * 因此在设置时间戳前先判断当前的拥塞算法是否需要做时间采样。
	 */
	if (icsk->icsk_ca_ops->flags & TCP_CONG_RTT_STAMP)
		__net_timestamp(skb);

	/* 根据传递进来的clone_it参数来确定是否需要克隆待发送的报文 */
	if (likely(clone_it)) {
		/* 如果skb已经被clone，则只能复制该skb的数据到新分配的skb中 */
		if (unlikely(skb_cloned(skb)))
			skb = pskb_copy(skb, gfp_mask);
		else
			/* clone新的skb */
			skb = skb_clone(skb, gfp_mask);
		if (unlikely(!skb))
			return -ENOBUFS;
	}

	/* 获取INET层和TCP层的传输控制块、skb中的TCP私有数据块 */
	inet = inet_sk(sk);
	tp = tcp_sk(sk);
	tcb = TCP_SKB_CB(skb);
	memset(&opts, 0, sizeof(opts));

	/* 根据TCP选项重新调整TCP首部的长度。*/
	/* 判断当前TCP报文是否是SYN段，因为有些选项只能出现在SYN报文中，需做特别处理。*/
	if (unlikely(tcb->flags & TCPCB_FLAG_SYN))
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
	else
		tcp_options_size = tcp_established_options(sk, skb, &opts,
							   &md5);
	/* tcp首部的总长度等于可选长度加上struct tcphdr */
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	/* 如果已发出但未确认的数据包数目为零，则只初始化拥塞控制，并开始跟踪该连接的RTT */
	if (tcp_packets_in_flight(tp) == 0) {
		tcp_ca_event(sk, CA_EVENT_TX_START);
		skb->ooo_okay = 1;
	} else
		skb->ooo_okay = 0;

	/* 调用skb_push()在数据部分的头部添加TCP首部，长度即为之前计算得到的那个tcp_header_size，
	 * 实际上是把data指针往上移 
	 */
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	/* SKB已添加到发送队列中，但是从SKB的角度去看还不知道他是属于哪个传输控制块，
	 * 因此调用skb_set_owner_w设置该SKB的宿主 
	 */
	skb_set_owner_w(skb, sk);

	/* Build TCP header and checksum it. */
	/* 填充TCP首部中的源端口source、目的端口dest、TCP报文的序号seq、确认序号ack_seq以及各个标志位 */
	th = tcp_hdr(skb);
	th->source		= inet->sport;
	th->dest		= inet->dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(tp->rcv_nxt);
	/* 设置TCP头长度和标志位 */
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->flags);

	/* 分两种情况设置TCP首部的接收窗口的大小 */
	if (unlikely(tcb->flags & TCPCB_FLAG_SYN)) {
		/* RFC1323: The window in SYN & SYN/ACK segments
		 * is never scaled.
		 */
		/* 如果是SYN段，则设置接收窗口初始值为rcv_wnd */
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	} else {
		/* 如果是其他的报文，则调用tcp_select_window()计算当前接收窗口的大小 */
		th->window	= htons(tcp_select_window(sk));
	}
	/* 初始化TCP首部的校验码和紧急指针，具体请参考TCP协议中的首部定义 */
	th->check		= 0;
	th->urg_ptr		= 0;

	/* The urg_mode check is necessary during a below snd_una win probe */
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			th->urg = 1;
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			th->urg_ptr = 0xFFFF;
			th->urg = 1;
		}
	}

	/* 写TCP选项 */
	tcp_options_write((__be32 *)(th + 1), tp, &opts, &md5_hash_location);
	if (likely((tcb->flags & TCPCB_FLAG_SYN) == 0))
		TCP_ECN_send(sk, skb, tcp_header_size);

#ifdef CONFIG_TCP_MD5SIG
	/* Calculate the MD5 hash, as we have all we need now */
	if (md5) {
		sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
		tp->af_specific->calc_md5_hash(md5_hash_location,
					       md5, sk, NULL, skb);
	}
#endif
	/* 这里计算checksum, 指向tcp_v4_send_check() */
	icsk->icsk_af_ops->send_check(sk, skb->len, skb);

	/* 当成功发送ACK时，会删除延迟确认定时器，
	 * 同时清零ACK的发送状态标志icsk->icsk_ack.pending 
	 */
	if (likely(tcb->flags & TCPCB_FLAG_ACK))
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb));

	/* 如果携带数据, 则判断是否需要重启拥塞窗口 以及 是否进入延迟确认模式 */
	if (skb->len != tcp_header_size)
		tcp_event_data_sent(tp, skb, sk);

	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTSEGS);

	/* 调用发送接口queue_xmit发送报文，进入到ip层，如果失败返回错误码。在TCP中该接口实现函数为ip_queue_xmit() */
	err = icsk->icsk_af_ops->queue_xmit(skb, 0);
	if (likely(err <= 0))
		return err;

	tcp_enter_cwr(sk, 1);

	return net_xmit_eval(err);
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	tp->write_seq = TCP_SKB_CB(skb)->end_seq;
	skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
}

/* Initialize TSO segments for a packet. */
static void tcp_set_skb_tso_segs(struct sock *sk, struct sk_buff *skb,
				 unsigned int mss_now)
{
	/* 有以下情况则不需要分片： 
	 * 1. 数据的长度不超过最大长度MSS 
	 * 2. 网卡不支持GSO 
	 * 3. 网卡不支持重新计算校验和
	 */
	if (skb->len <= mss_now || !sk_can_gso(sk) ||
	    skb->ip_summed == CHECKSUM_NONE) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		skb_shinfo(skb)->gso_segs = 1;
		skb_shinfo(skb)->gso_size = 0;
		skb_shinfo(skb)->gso_type = 0;
	} else {
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss_now); /* 计算需要分成几个数据段, 向上取整 */
		skb_shinfo(skb)->gso_size = mss_now; /* 每个数据段的大小 */
		skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	}
}

/* When a modification to fackets out becomes necessary, we need to check
 * skb is counted to fackets_out or not.
 */
static void tcp_adjust_fackets_out(struct sock *sk, struct sk_buff *skb,
				   int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->sacked_out || tcp_is_reno(tp))
		return;

	if (after(tcp_highest_sack_seq(tp), TCP_SKB_CB(skb)->seq))
		tp->fackets_out -= decr;
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
static void tcp_adjust_pcount(struct sock *sk, struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->packets_out -= decr;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;

	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);

	tcp_adjust_fackets_out(sk, skb, decr);

	if (tp->lost_skb_hint &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
	    (tcp_is_fack(tp) || (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)))
		tp->lost_cnt_hint -= decr;

	tcp_verify_left_out(tp);
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int tcp_fragment(struct sock *sk, struct sk_buff *skb, u32 len,
		 unsigned int mss_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	int nlen;
	u8 flags;

	BUG_ON(len > skb->len); /* 切片大小不能超过skb数据大小 */

	nsize = skb_headlen(skb) - len; /* nsize为下一个skb要分配的线性空间大小 */
	if (nsize < 0)
		nsize = 0;

	/* 如果skb被clone过，即数据空间共享，并且含有非线性空间
	 * 那么使用pskb_expand_head先复制单独的线性空间
	 */
	if (skb_cloned(skb) &&
	    skb_is_nonlinear(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	/* 分配一个新的skb */
	buff = sk_stream_alloc_skb(sk, nsize, GFP_ATOMIC);
	if (buff == NULL)
		return -ENOMEM; /* We'll just try again later. */

	sk->sk_wmem_queued += buff->truesize; /* 增加sk已分配 */
	sk_mem_charge(sk, buff->truesize); /* 减小sk预分配 */
	nlen = skb->len - len - nsize; /* nlen为下个skb非线性大小 */
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len; /* 下个skb的seq */
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq; /* 下个skb的end_seq */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq; /* 原skb的end_seq */

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;
	TCP_SKB_CB(skb)->flags = flags & ~(TCPCB_FLAG_FIN | TCPCB_FLAG_PSH); /* 原skb需要去掉FIN和PSH标志 */
	TCP_SKB_CB(buff)->flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;

	/* 如果skb没有分片，即是线性的 并且数据部分的checksum需要协议计算 */	
	if (!skb_shinfo(skb)->nr_frags && skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Copy and checksum data tail into the new buffer. */
		/* 将skb线性空间分割后剩余的数据拷贝到下个skb的线性空间并计算checksum */
		buff->csum = csum_partial_copy_nocheck(skb->data + len,
						       skb_put(buff, nsize),
						       nsize, 0);

		skb_trim(skb, len); /* 将skb数据长度设置为len */

		skb->csum = csum_block_sub(skb->csum, buff->csum, len);
	} else {
		skb->ip_summed = CHECKSUM_PARTIAL; /* 由硬件计算checksum */
		skb_split(skb, buff, len); /* 将skb数据分割转移到下个skb中 */
	}

	buff->ip_summed = skb->ip_summed;

	/* Looks stupid, but our code really uses when of
	 * skbs, which it never sent before. --ANK
	 */
	TCP_SKB_CB(buff)->when = TCP_SKB_CB(skb)->when;
	buff->tstamp = skb->tstamp;

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	/* 修复下分段 */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	/* 如果skb已经发送出去了，那么可能因为分割后pcount段数不一致，
	 * 这时需要调整tp中的成员，比如packets_out/sacked_out等等
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk); /* 把buff插入到skb后面 */

	return 0;
}

/* This is similar to __pskb_pull_head() (it will go to core/skbuff.c
 * eventually). The difference is that pulled data not copied, but
 * immediately discarded.
 */
static void __pskb_trim_head(struct sk_buff *skb, int len)
{
	int i, k, eat;

	eat = len;
	k = 0;
	/* 把截掉的分页put_gage掉，并把后面的分页往前挪 */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		if (skb_shinfo(skb)->frags[i].size <= eat) {
			put_page(skb_shinfo(skb)->frags[i].page);
			eat -= skb_shinfo(skb)->frags[i].size;
		} else {
			skb_shinfo(skb)->frags[k] = skb_shinfo(skb)->frags[i];
			if (eat) {
				skb_shinfo(skb)->frags[k].page_offset += eat;
				skb_shinfo(skb)->frags[k].size -= eat;
				eat = 0;
			}
			k++;
		}
	}
	skb_shinfo(skb)->nr_frags = k; /* 新的分页个数 */

	skb_reset_tail_pointer(skb); /* 线性空间长度现在为0了 */
	skb->data_len -= len;
	skb->len = skb->data_len;
}

/* Remove acked data from a packet in the transmit queue. */
int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	/* 如果skb被clone过，先使用pskb_expand_head使得线性空间独立 */
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -ENOMEM;

	/* If len == headlen, we avoid __skb_pull to preserve alignment. */
	/* 如果截掉的数据小于线性长度，直接改变data和len即可 */
	if (unlikely(len < skb_headlen(skb)))
		__skb_pull(skb, len);
	else /* 截掉数据超过线性空间，还需要处理分页 */
		__pskb_trim_head(skb, len - skb_headlen(skb));

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb->truesize	     -= len;
	sk->sk_wmem_queued   -= len;
	sk_mem_uncharge(sk, len);
	sock_set_flag(sk, SOCK_QUEUE_SHRUNK);

	/* Any change of skb->len requires recalculation of tso
	 * factor and mss.
	 */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(sk, skb, tcp_current_mss(sk));

	return 0;
}

/* Calculate MSS. Not accounting for SACKs here.  */
/* 将MTU转成MSS大小, 即减去IP头和TCP头大小, 但是没减去动态的SACK段大小 */
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	/* mss = mtu - IP头大小 - TCP头大小 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);

	/* Clamp it (mss_clamp does not include tcp options) */
	/* 如果比SYN包中的MSS大则去SYN包的大小 */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	/* 再减去IP头选项大小 */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	/* MSS不能小于48 */
	if (mss_now < 48)
		mss_now = 48;

	/* Now subtract TCP options size, not including SACKs */
	/* 再减去TCP头固定的选项大小 */
	mss_now -= tp->tcp_header_len - sizeof(struct tcphdr);

	return mss_now;
}

/* Inverse of above */
/* 将mss转成mtu, 即mss+ip头+tcp头*/
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;

	mtu = mss +
	      tp->tcp_header_len + /* 固定TCP头 */
	      icsk->icsk_ext_hdr_len + /* IP头选项 */
	      icsk->icsk_af_ops->net_header_len; /* 固定IP头 */

	return mtu;
}

/* MTU probing init per socket */
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	icsk->icsk_mtup.enabled = sysctl_tcp_mtu_probing > 1; /* 大于1表示直接启用mtu探测 */
	/* search_high为mtu, 即mss+tcp头+ip头 */
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
			       icsk->icsk_af_ops->net_header_len;
	/* search_low为mss512对应mtu */
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, sysctl_tcp_base_mss);
	icsk->icsk_mtup.probe_size = 0;
}

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
/* 通过MTU维护MSS: tp->mss_cache */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* mtu变小了, search_high也要相应变小 */
	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;

	mss_now = tcp_mtu_to_mss(sk, pmtu); /* 将MTU转成MSS */
	mss_now = tcp_bound_to_half_wnd(tp, mss_now); /* 如果大于接收窗口一半则为接收窗口一半 */

	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu; /* 保存MTU值, 该变量只有这里维护 */
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now; /* 保存tp->mss_cache, 该变量只有这里维护 */

	return mss_now;
}

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
/* 返回当前的MSS大小, 且减去了当前需要发送的TCP选项大小 */
unsigned int tcp_current_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;

	mss_now = tp->mss_cache; /* 当前静态MSS大小(未考虑SACK段等动态大小) */

	if (dst) {
		u32 mtu = dst_mtu(dst); /* 从路由缓存获取MTU大小 */
		/* 如果MTU变了, 那么MSS也需要跟着改变, tcp_sync_mss()会维护tp->mss_cache */
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
	}

	/* header_len为TCP首部大小(包括选项)*/
	header_len = tcp_established_options(sk, NULL, &opts, &md5) + /* 返回TCP选项大小 */
		     sizeof(struct tcphdr); /* 再加上基础首部大小 */
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	/* tp->tcp_header_len为TCP固定首部大小(包括固定选项如timestamp) 
	 * 不相等说明此时需要发送SACK段, 所以mss需要再减去TCP选项多出的大小
	 */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now; /* 返回当前的MSS */
}

/* Congestion window validation. (RFC2861) */
/* 在发送方成功发送数据包后，会检查从发送队列发出而未确认的数据包是否用完拥塞窗口。
 * 如果拥塞窗口被用完了，说明发送方收到网络限制；
 * 如果拥塞窗口没被用完，且距离上次检查时间超过了RTO，说明发送方收到应用程序限制
 */
static void tcp_cwnd_validate(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->packets_out >= tp->snd_cwnd) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_time_stamp; /* 更新检测时间 */
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out; /* 更新已使用窗口 */

		/* 如果距离上次检测的时间，即距离上次发包时间已经超过RTO */
		if (sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_time_stamp - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto)
			tcp_cwnd_application_limited(sk);
	}
}

/* Returns the portion of skb which can be sent right away without
 * introducing MSS oddities to segment boundaries. In rare cases where
 * mss_now != mss_cache, we will request caller to create a small skb
 * per input skb which could be mostly avoided here (if desired).
 *
 * We explicitly want to create a request for splitting write queue tail
 * to a small skb for Nagle purposes while avoiding unnecessary modulos,
 * thus all the complexity (cwnd_len is always MSS multiple which we
 * return whenever allowed by the other factors). Basically we need the
 * modulo only when the receiver window alone is the limiting factor or
 * when we would be allowed to send the split-due-to-Nagle skb fully.
 */
static unsigned int tcp_mss_split_point(struct sock *sk, struct sk_buff *skb,
					unsigned int mss_now, unsigned int cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 needed, window, cwnd_len;

	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	cwnd_len = mss_now * cwnd;

	/* 拥塞窗口比接收窗口较小，返回拥塞窗口大小 */
	if (likely(cwnd_len <= window && skb != tcp_write_queue_tail(sk)))
		return cwnd_len;

	needed = min(skb->len, window);

	if (cwnd_len <= needed) /* 拥塞窗口小于数据包大小或者接收窗口, 返回拥塞窗口大小 */
		return cwnd_len;

	return needed - needed % mss_now; /* 这里返回在接收窗口内的数据包大小，取整到MSS */
}

/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int tcp_cwnd_test(struct tcp_sock *tp,
					 struct sk_buff *skb)
{
	u32 in_flight, cwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	/* 对FIN包不检测，让他通过* */
	if ((TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = tcp_packets_in_flight(tp); /* 计算正在网络上传输的包数目 */
	cwnd = tp->snd_cwnd; /* 获取当前拥塞窗口的大小，snd_cwnd表示当前拥塞窗口的大小 */
	if (in_flight < cwnd)
		return (cwnd - in_flight); /* 返回剩余的可发送的包个数 */

	return 0;
}

/* Intialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int tcp_init_tso_segs(struct sock *sk, struct sk_buff *skb,
			     unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);

	/* 如果还没有分段，或者有多个分段但是分段长度不等于当前MSS，则需处理 */
	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_set_skb_tso_segs(sk, skb, mss_now);
		tso_segs = tcp_skb_pcount(skb); /* 重新获取分段数量 */
	}
	return tso_segs;
}

/* Minshall's variant of the Nagle send check. */
static inline int tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Return 0, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized.
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_NODELAY was set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static inline int tcp_nagle_check(const struct tcp_sock *tp,
				  const struct sk_buff *skb,
				  unsigned mss_now, int nonagle)
{
	return (skb->len < mss_now &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out && tcp_minshall_check(tp))));
}

/* Return non-zero if the Nagle test allows this packet to be
 * sent now.
 */
static inline int tcp_nagle_test(struct tcp_sock *tp, struct sk_buff *skb,
				 unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return 1;

	/* Don't use the nagle rule for urgent data (or for the final FIN).
	 * Nagle can be ignored during F-RTO too (see RFC4138).
	 */
	if (tcp_urg_mode(tp) || (tp->frto_counter == 2) ||
	    (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN))
		return 1;

	if (!tcp_nagle_check(tp, skb, cur_mss, nonagle))
		return 1;

	return 0;
}

/* Does at least the first segment of SKB fit into the send window? */
static inline int tcp_snd_wnd_test(struct tcp_sock *tp, struct sk_buff *skb,
				   unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	return !after(end_seq, tcp_wnd_end(tp));
}

/* This checks if the data bearing packet SKB (usually tcp_send_head(sk))
 * should be put on the wire right now.  If so, it returns the number of
 * packets allowed by the congestion window.
 */
static unsigned int tcp_snd_test(struct sock *sk, struct sk_buff *skb,
				 unsigned int cur_mss, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cwnd_quota;

	tcp_init_tso_segs(sk, skb, cur_mss);

	if (!tcp_nagle_test(tp, skb, cur_mss, nonagle))
		return 0;

	cwnd_quota = tcp_cwnd_test(tp, skb);
	if (cwnd_quota && !tcp_snd_wnd_test(tp, skb, cur_mss))
		cwnd_quota = 0;

	return cwnd_quota;
}

/* Test if sending is allowed right now. */
int tcp_may_send_now(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_send_head(sk);

	return (skb &&
		tcp_snd_test(sk, skb, tcp_current_mss(sk),
			     (tcp_skb_is_last(sk, skb) ?
			      tp->nonagle : TCP_NAGLE_PUSH)));
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
static int tso_fragment(struct sock *sk, struct sk_buff *skb, unsigned int len,
			unsigned int mss_now)
{
	struct sk_buff *buff;
	int nlen = skb->len - len;
	u8 flags;

	/* All of a TSO frame must be composed of paged data.  */
	/* 如果含有线性的数据则直接调用tcp_fragment */
	if (skb->len != skb->data_len)
		return tcp_fragment(sk, skb, len, mss_now);

	buff = sk_stream_alloc_skb(sk, 0, GFP_ATOMIC);
	if (unlikely(buff == NULL))
		return -ENOMEM;

	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->flags;
	TCP_SKB_CB(skb)->flags = flags & ~(TCPCB_FLAG_FIN | TCPCB_FLAG_PSH);
	TCP_SKB_CB(buff)->flags = flags;

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;

	buff->ip_summed = skb->ip_summed = CHECKSUM_PARTIAL;
	skb_split(skb, buff, len);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(sk, skb, mss_now);
	tcp_set_skb_tso_segs(sk, buff, mss_now);

	/* Link BUFF into the send queue. */
	skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk);

	return 0;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
static int tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 send_win, cong_win, limit, in_flight;

	/* FIN包立即发送 */
	if (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN)
		goto send_now;

	/* 非OPEN态立即发送 */
	if (icsk->icsk_ca_state != TCP_CA_Open)
		goto send_now;

	/* TSO段延时超过2个时钟滴答 立即发送 */
	/* Defer for less than two clock ticks. */
	if (tp->tso_deferred &&
	    (((u32)jiffies << 1) >> 1) - (tp->tso_deferred >> 1) > 1)
		goto send_now;

	in_flight = tcp_packets_in_flight(tp);

	BUG_ON(tcp_skb_pcount(skb) <= 1 || (tp->snd_cwnd <= in_flight));

	send_win = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
	cong_win = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	limit = min(send_win, cong_win);
	/* 拥塞窗口和发送窗口的最小值大于64K或三倍的当前有效MSS,立即发送 */
	/* If a full-sized TSO skb can be sent, do it. */
	if (limit >= sk->sk_gso_max_size)
		goto send_now;

	/* Middle in queue won't get any more data, full sendable already? */
	if ((skb != tcp_write_queue_tail(sk)) && (limit >= skb->len))
		goto send_now;

	if (sysctl_tcp_tso_win_divisor) {
		u32 chunk = min(tp->snd_wnd, tp->snd_cwnd * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= sysctl_tcp_tso_win_divisor;
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
		if (limit > tcp_max_burst(tp) * tp->mss_cache)
			goto send_now;
	}

	/* Ok, it looks like it is advisable to defer.  */
	tp->tso_deferred = 1 | (jiffies << 1);

	return 1;

send_now:
	tp->tso_deferred = 0;
	return 0;
}

/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
static int tcp_mtu_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb, *nskb, *next;
	int len;
	int probe_size;
	int size_needed;
	int copy;
	int mss_now;

	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off) */
	if (!icsk->icsk_mtup.enabled ||	/* 没有启用MTU探测 */
	    icsk->icsk_mtup.probe_size || /* 已经正在进行PMTU探测 */
	    inet_csk(sk)->icsk_ca_state != TCP_CA_Open || /* 非OPEN状态不使用 */
	    tp->snd_cwnd < 11 || /* 窗口太小也不使用 */
	    tp->rx_opt.num_sacks || tp->rx_opt.dsack) /* 需要发送SACK/DSACK时也不使用 */
		return -1;

	/* Very simple search strategy: just double the MSS. */
	mss_now = tcp_current_mss(sk); /* 得到当前MSS */
	probe_size = 2 * tp->mss_cache; /* 设置探测包大小为当前MSS的两倍 */
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	if (probe_size > tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_high)) {
		/* TODO: set timer for probe_converge_event */
		return -1;
	}

	/* Have enough data in the send queue to probe? */
	/* 需要至少还有size_needed的数据未发送 */
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	/* 接收窗口需要至少size_needed */
	if (tp->snd_wnd < size_needed)
		return -1;
	/* 如果size_needed数据因为接收窗口占用了不能马上发送，则等待 */
	if (after(tp->snd_nxt + size_needed, tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight, don't stall */
	/* 如果inflight将近发满cwnd, 则等待 */
	if (tcp_packets_in_flight(tp) + 2 > tp->snd_cwnd) {
		if (!tcp_packets_in_flight(tp)) /* inflight为0时不探测 */
			return -1;
		else
			return 0; /* 等待 */
	}

	/* 到了这里可以发送mtu探测包了 */

	/* We're allowed to probe.  Build it now. */
	/* 首先申请了probe_size的skb */
	if ((nskb = sk_stream_alloc_skb(sk, probe_size, GFP_ATOMIC)) == NULL)
		return -1;
	/* 增加sk使用的写缓存 */
	sk->sk_wmem_queued += nskb->truesize;
	sk_mem_charge(sk, nskb->truesize);

	skb = tcp_send_head(sk); /* 取出待发送的skb */

	/* 初始化seq等 */
	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;
	TCP_SKB_CB(nskb)->flags = TCPCB_FLAG_ACK;
	TCP_SKB_CB(nskb)->sacked = 0;
	nskb->csum = 0;
	nskb->ip_summed = skb->ip_summed;

	tcp_insert_write_queue_before(nskb, skb, sk); /* 将新的skb插入到待发送的前面 */

	len = 0;
	/* 这里从skb开始拷贝probe_size的数据到nskb, 并释放被拷贝的skb */
	tcp_for_write_queue_from_safe(skb, next, sk) {
		copy = min_t(int, skb->len, probe_size - len); /* 拷贝的长度 */
		if (nskb->ip_summed) /* 如果网卡计算checksum就直接拷贝 */
			skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);
		else /* 否则边拷贝边计算checksum到nskb->csum中 */
			nskb->csum = skb_copy_and_csum_bits(skb, 0,
							    skb_put(nskb, copy),
							    copy, nskb->csum);

		if (skb->len <= copy) { /* 该skb数据全部被拷贝了, 删掉skb */
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->flags |= TCP_SKB_CB(skb)->flags;
			tcp_unlink_write_queue(skb, sk);
			sk_wmem_free_skb(sk, skb);
		} else { /* skb还有数据, 那么就得截掉被拷贝的copy长度 */
			/* 复制flags, 除了FIN和PSH标志 */
			TCP_SKB_CB(nskb)->flags |= TCP_SKB_CB(skb)->flags &
						   ~(TCPCB_FLAG_FIN|TCPCB_FLAG_PSH);
			/* 如果skb没有分页,那么直接调整线性区即可, 并重新计算checksum */
			if (!skb_shinfo(skb)->nr_frags) {
				skb_pull(skb, copy);
				if (skb->ip_summed != CHECKSUM_PARTIAL)
					skb->csum = csum_partial(skb->data,
								 skb->len, 0);
			} else { /* 否则截掉copy的长度, 重新设置tso_segs */
				__pskb_trim_head(skb, copy);
				tcp_set_skb_tso_segs(sk, skb, mss_now);
			}
			TCP_SKB_CB(skb)->seq += copy; /* 调整序列号 */
		}

		len += copy;

		if (len >= probe_size) /* 拷贝了probe_size的数据退出 */
			break;
	}
	/* 初始化tso_segs, 注意此时是以nskb->len为mss来计算segs的, 
	 * 也就是探测包的gso_segs只为1
	 */
	tcp_init_tso_segs(sk, nskb, nskb->len); 

	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit(). */
	TCP_SKB_CB(nskb)->when = tcp_time_stamp; /* 发送时间戳 */
	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) { /* 发送探测包 */
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		/* 这里数据包发送出去了, 因为我们发送了一个两倍当前mss的大包, 
		 * 所以cwnd要相应减一
		 */
		tp->snd_cwnd--;
		tcp_event_new_data_sent(sk, nskb);

		/* 记录此次探测的MTU值 */
		icsk->icsk_mtup.probe_size = tcp_mss_to_mtu(sk, nskb->len);
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;

		return 1;
	}

	return -1;
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * LARGESEND note: !tcp_urg_mode is overkill, only frames between
 * snd_up-64k-mss .. snd_up cannot be large. However, taking into
 * account rare use of URG, this is not a big flaw.
 *
 * Returns 1, if no segments are in flight and we have queued segments, but
 * cannot send anything now because of SWS or another problem.
 */
/* 
 * 将发送队列上的SKB发送出去，返回值为0表示发送成功 
 * 函数执行过程如下：
 * 1、检测拥塞窗口的大小。
 * 2、检测当前报文是否完全处在发送窗口内。
 * 3、检测报文是否使用nagle算法进行发送。
 * 4、通过以上检测后将该SKB发送出去。
 * 5、循环检测发送队列上所有未发送的SKB。
 *
 */
static int tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			  int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;

	sent_pkts = 0;	/* sent_pkts用来统计函数中已发送报文总数 */

	/* 发送一个路径MTU探测报文，如果成功则发送报文数加1 */
	if (!push_one) {
		/* 如果要发送多个skb，则需要检测MTU。
		 * 这时会检测MTU，希望MTU可以比之前的大，提高发送效率
		 */
		/* Do MTU probing. */
		result = tcp_mtu_probe(sk);
		if (!result) {
			return 0;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	/* 如果发送队列不为空，则准备开始发送报文 */
	while ((skb = tcp_send_head(sk))) {
		unsigned int limit;

		/* 设置有关TSO的信息，包括GSO类型，GSO分段的大小等等。
		 * 这些信息是准备给软件TSO分段使用的。
		 * 如果网络设备不支持TSO，但又使用了TSO功能，
		 * 则报文在提交给网络设备之前，需进行软分段，即由代码实现TSO分段
		 */
		tso_segs = tcp_init_tso_segs(sk, skb, mss_now);
		BUG_ON(!tso_segs);

		/* 检测拥塞窗口的大小，如果为0，则说明拥塞窗口已满，目前不能发送。
		 * 拿拥塞窗口和正在网络上传输的包数目相比，
		 * 如果拥塞窗口大，则返回拥塞窗口减掉正在网络上传输的包数目后剩下的大小。
		 * 该函数目的是判断正在网络上传输的包数目是否超过拥塞窗口，如果超过了，则不发送。
		 */
		cwnd_quota = tcp_cwnd_test(tp, skb);
		if (!cwnd_quota)
			break;

		/* 检测当前报文是否完全处于发送窗口内，如果是则可以发送，否则不能发送 */
		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now)))
			break;

		if (tso_segs == 1) { /* tso_segs=1 表示无需tso分段 */
			/* 根据nagle算法，计算是否需要发送数据 */
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
		} else {
			/* 如果需要TSO分段，则检测该报文是否应该延时发送。
			 * tcp_tso_should_defer()用来检测GSO段是否需要延时发送。
			 * 在段中有FIN标志，或者不处于open拥塞状态，
			 * 或者TSO段延时超过2个时钟滴答，或者拥塞窗口和发送窗口的最小值大于64K或三倍的当前有效MSS，
			 * 在这些情况下会立即发送，而其他情况下会延时发送，
			 * 这样主要是为了减少软GSO分段的次数，以提高性能
			 */
			if (!push_one && tcp_tso_should_defer(sk, skb))
				break;
		}

		limit = mss_now; /* limit为再次分段的段长，初始化为当前MSS */

		/* 在TSO分片大于1并且不是URG模式下，通过mss_now计算limit的值
		 * 以发送窗口和拥塞窗口的最小值作为分段段长
		 */
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    cwnd_quota);

		/* 如果SKB中的数据长度大于分段段长，则调用tso_fragment()根据该段长进行分段，
		 * 如果分段失败则暂不发送 
		 */
		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, skb, limit, mss_now)))
			break;

		/* 更新TCP时间戳，记录此报文发送的时间 */
		TCP_SKB_CB(skb)->when = tcp_time_stamp;

		/* 调用tcp_transmit_skb()发送TCP段，
		 * 其中第三个参数1表示是否需要克隆被发送的报文
		 */
		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		/* 通过tcp_event_new_data_sent()调用tcp_advance_send_head()更新sk_send_head，
		 * 即取发送队列中的下一个SKB。
		 * 同时更新snd_nxt，即等待发送的下一个TCP段的序号，然后统计发出但未得到确认的数据报个数。
		 * 最后如果发送该报文前没有需要确认的报文，则复位重传定时器，
		 * 对本次发送的报文做重传超时计时
		 */
		tcp_event_new_data_sent(sk, skb);

		/* 更新struct tcp_sock中的snd_sml字段。
		 * snd_sml表示最近发送的小包(小于MSS的段)的最后一个字节序号，
		 * 在发送成功后，如果报文小于MSS，即更新该字段，
		 * 主要用来判断是否启动nagle算法
		 */
		tcp_minshall_update(tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb); /* 更新已发送报文总数 */

		if (push_one)
			break;
	}
	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Recovery)
		tp->prr_out += sent_pkts;

	/* 如果本次有数据发送，则对TCP拥塞窗口进行检查确认 */
	if (likely(sent_pkts)) {
		tcp_cwnd_validate(sk);
		return 0;
	}

	/* 如果本次没有数据发送，则根据已发送但未确认的报文数packets_out和sk_send_head返回，
	 * packets_out不为零或sk_send_head为空都视为有数据发出，因此返回成功 
	 */
	return !tp->packets_out && tcp_send_head(sk); /* 如果没有发送的数据并且还有数据待发送，则返回1去激活0窗口定时器 */
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	struct sk_buff *skb = tcp_send_head(sk);

	if (!skb)
		return;

	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (tcp_write_xmit(sk, cur_mss, nonagle, 0, GFP_ATOMIC))
		tcp_check_probe_timer(sk); /* 如果tcp_write_xmit()没发送任何数据并还有数据待发送，则激活0窗口定时器 */
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
void tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = tcp_send_head(sk);

	BUG_ON(!skb || skb->len < mss_now);

	tcp_write_xmit(sk, mss_now, TCP_NAGLE_PUSH, 1, sk->sk_allocation);
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = icsk->icsk_ack.rcv_mss; /* 这个是估计目前对端有效的发送mss，而不是最大的 */
	int free_space = tcp_space(sk); /* 剩余接收缓存大小的3/4 */
	int full_space = min_t(int, tp->window_clamp, tcp_full_space(sk)); /* 总的接收缓存大小的3/4 */
	int window;

	/* 减小mss，因为接收缓存太小了 */
	if (mss > full_space)
		mss = full_space;

	/* 接收缓存使用一半以上时要小心了 */
	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0; /* 可以快速发送ACK段的数量置零 */

		if (tcp_memory_pressure) /* 有内存压力时，把接收窗口限制在5840字节以下 */
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		if (free_space < mss) /* 剩余接收缓存不足以接收mss的数据, 返回0窗口 */
			return 0;
	}

	/* 不能超过当前接收窗口阈值，这可以达接收窗口平滑增长的效果 */
	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	window = tp->rcv_wnd;
	if (tp->rx_opt.rcv_wscale) { /* 接收窗口扩大因子不为零 */
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		/* 防止四舍五入造成通告的接收窗口偏小 */
		if (((window >> tp->rx_opt.rcv_wscale) << tp->rx_opt.rcv_wscale) != window)
			window = (((window >> tp->rx_opt.rcv_wscale) + 1)
				  << tp->rx_opt.rcv_wscale);
	} else {
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		/* 截取free_space中整数个mss，如果rcv_wnd和free_space的差距在一个mss以上 */
		if (window <= free_space - mss || window > free_space)
			window = (free_space / mss) * mss;
		/* 如果free space过小，则直接取free space值 */
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
		/* 当free_space - mss < window < free_space时，直接使用rcv_wnd，不做修改 */
	}

	return window;
}

/* Collapses two adjacent SKB's during retransmission. */
/* 将skb与下一个skb合并(两个都是小包) */
static void tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = tcp_write_queue_next(sk, skb); /* 下一个skb */
	int skb_size, next_skb_size;

	skb_size = skb->len;
	next_skb_size = next_skb->len;

	/* 这两个skb都不能超过一个MSS */
	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	/* 如果next_skb正好是highest_sack指向，则改为skb */
	tcp_highest_sack_combine(sk, next_skb, skb);

	/* 把next_skb从链表中除去 */
	tcp_unlink_write_queue(next_skb, sk);

	/* 把next_skb的数据拷贝到skb的线性空间中 */
	skb_copy_from_linear_data(next_skb, skb_put(skb, next_skb_size),
				  next_skb_size);

	/* 如果next_skb由硬件计算checksum，则skb也需要硬件计算 */
	if (next_skb->ip_summed == CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_PARTIAL;

	/* 如果两个skb都由协议计算checksum, 那么可以相加 */
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq; /* 更新end_seq */

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->flags |= TCP_SKB_CB(next_skb)->flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb)); /* 调整tp成员包个数 */

	sk_wmem_free_skb(sk, next_skb); /* 将next_skb释放掉 */
}

/* Check if coalescing SKBs is legal. */
static int tcp_can_collapse(struct sock *sk, struct sk_buff *skb)
{
	if (tcp_skb_pcount(skb) > 1)
		return 0;
	/* TODO: SACK collapsing could be used to remove this condition */
	if (skb_shinfo(skb)->nr_frags != 0)
		return 0;
	if (skb_cloned(skb))
		return 0;
	if (skb == tcp_send_head(sk))
		return 0;
	/* Some heurestics for collapsing over SACK'd could be invented */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return 0;

	return 1;
}

/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
				     int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	int first = 1;

	if (!sysctl_tcp_retrans_collapse)
		return;
	if (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_SYN)
		return;

	tcp_for_write_queue_from_safe(skb, tmp, sk) {
		if (!tcp_can_collapse(sk, skb)) /* 判断可以合并的条件 */
			break;

		space -= skb->len;

		if (first) { /* 首个包跳过 */
			first = 0;
			continue;
		}

		if (space < 0) /* 超出一个MSS，退出 */
			break;
		/* Punt if not enough space exists in the first SKB for
		 * the data in the second
		 */
		if (skb->len > skb_tailroom(to)) /* 尾部空间不足，退出 */
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp))) /* 超出接收窗口，退出 */
			break;

		tcp_collapse_retrans(sk, to); /* 将下一个skb合并到to中 */
	}
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int cur_mss;
	int err;

	/* Inconslusive MTU probe */
	/* 如果正在使用MTU探测, 这里重传说明探测包丢失了, 
	 * 所以这里probe_size置0结束探测
	 */
	if (icsk->icsk_mtup.probe_size) {
		icsk->icsk_mtup.probe_size = 0;
	}

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	/* 如果消耗很多的内存做其他事，那么就没有多余的来做队列的处理了 */
	if (atomic_read(&sk->sk_wmem_alloc) >
	    min(sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2), sk->sk_sndbuf))
		return -EAGAIN;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) { /* 说明是有一部分数据才需要重传，形如：seq---snd_una---end_seq，前面一半已收到ACK */
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una)) /* 说明全部ACK，无需重传，BUG */
			BUG();
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq)) /* 裁掉已经重传过的数据 */
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))
	    && TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	if (skb->len > cur_mss) { /* 重传时大于MSS要先分片 */
		if (tcp_fragment(sk, skb, cur_mss, cur_mss))
			return -ENOMEM; /* We'll try again later. */
	} else {
		int oldpcount = tcp_skb_pcount(skb);

		if (unlikely(oldpcount > 1)) { /* 说明当前MSS和SKB的分片大小不匹配，需要重新调整 */
			tcp_init_tso_segs(sk, skb, cur_mss);
			tcp_adjust_pcount(sk, skb, oldpcount - tcp_skb_pcount(skb)); /* pcount变了需要调整tp的成员 */
		}
	}

	/* 尝试将小包skb与接下来的小包skb合并成不超过mss的包 */
	tcp_retrans_try_collapse(sk, skb, cur_mss);

	/* Some Solaris stacks overoptimize and ignore the FIN on a
	 * retransmit when old data is attached.  So strip it off
	 * since it is cheap to do so and saves bytes on the network.
	 */
	if (skb->len > 0 &&
	    (TCP_SKB_CB(skb)->flags & TCPCB_FLAG_FIN) &&
	    tp->snd_una == (TCP_SKB_CB(skb)->end_seq - 1)) {
		if (!pskb_trim(skb, 0)) {
			/* Reuse, even though it does some unnecessary work */
			tcp_init_nondata_skb(skb, TCP_SKB_CB(skb)->end_seq - 1,
					     TCP_SKB_CB(skb)->flags);
			skb->ip_summed = CHECKSUM_NONE;
		}
	}

	/* Make a copy, if the first transmission SKB clone we made
	 * is still in somebody's hands, else make a clone.
	 */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;

	err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);

	if (err == 0) {
		/* Update global TCP statistics. */
		TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS);

		tp->total_retrans++;

#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
			if (net_ratelimit())
				printk(KERN_DEBUG "retrans_out leaked.\n");
		}
#endif
		if (!tp->retrans_out)
			tp->lost_retrans_low = tp->snd_nxt;
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);

		/* Save stamp of the first retransmit. */
		if (!tp->retrans_stamp)
			tp->retrans_stamp = TCP_SKB_CB(skb)->when;

		tp->undo_retrans += tcp_skb_pcount(skb);

		/* snd_nxt is stored to detect loss of retransmitted segment,
		 * see tcp_input.c tcp_sacktag_write_queue().
		 */
		/* 把这时的snd_nxt保存到重传包的ack_seq，用于在tcp_mark_lost_retrans()中判断重传包是否丢失 */
		TCP_SKB_CB(skb)->ack_seq = tp->snd_nxt;
	}
	return err;
}

/* Check if we forward retransmits are possible in the current
 * window/congestion state.
 */
static int tcp_can_forward_retransmit(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* Forward retransmissions are possible only during Recovery. */
	if (icsk->icsk_ca_state != TCP_CA_Recovery)
		return 0;

	/* No forward retransmissions in Reno are possible. */
	if (tcp_is_reno(tp))
		return 0;

	/* Yeah, we have to make difficult choice between forward transmission
	 * and retransmission... Both ways have their merits...
	 *
	 * For now we do not retransmit anything, while we have some new
	 * segments to send. In the other cases, follow rule 3 for
	 * NextSeg() specified in RFC3517.
	 */

	if (tcp_may_send_now(sk))
		return 0;

	return 1;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 * If doing SACK, the first ACK which comes back for a timeout
 * based retransmit packet might feed us FACK information again.
 * If so, we use it to avoid unnecessarily retransmissions.
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	struct sk_buff *hole = NULL;
	u32 last_lost;
	int mib_idx;
	int fwd_rexmitting = 0;

	if (!tp->packets_out) /* 没有发送的数据包，返回 */
		return;

	if (!tp->lost_out) /* 没有标记为LOSS的数据包，重置最高重传序列号 */
		tp->retransmit_high = tp->snd_una;

	if (tp->retransmit_skb_hint) { /* 如果有重传信息，则skb从之前的开始 */
		skb = tp->retransmit_skb_hint;
		last_lost = TCP_SKB_CB(skb)->end_seq;
		if (after(last_lost, tp->retransmit_high))
			last_lost = tp->retransmit_high;
	} else { /* 否则，skb从重传队列第一个包开始 */
		skb = tcp_write_queue_head(sk);
		last_lost = tp->snd_una;
	}

	tcp_for_write_queue_from(skb, sk) {
		__u8 sacked = TCP_SKB_CB(skb)->sacked;

		if (skb == tcp_send_head(sk))
			break;
		/* we could do better than to assign each time */
		if (hole == NULL)
			tp->retransmit_skb_hint = skb;

		/* Assume this retransmit will generate
		 * only one packet for congestion window
		 * calculation purposes.  This works because
		 * tcp_retransmit_skb() will chop up the
		 * packet to be MSS sized and all the
		 * packet counting works out.
		 */
		if (tcp_packets_in_flight(tp) >= tp->snd_cwnd) /* 超过拥塞窗口，不重传了 */
			return;

		if (fwd_rexmitting) { /* 向前重传 */
begin_fwd:
			/* 向前重传是重传从标记为丢失的最高序列号的skb到最高被sack过的skb. */
			if (!before(TCP_SKB_CB(skb)->seq, tcp_highest_sack_seq(tp)))
				break;
			mib_idx = LINUX_MIB_TCPFORWARDRETRANS;

		} else if (!before(TCP_SKB_CB(skb)->seq, tp->retransmit_high)) { /* skb->seq >= 最高标记为丢失的序列号 */
			/* 到达这里说明被标记为丢失的已经都重传过, 从本skb开始都是未被标记为丢失的数据包
			 *  
			 * 然后检查是否开启向前重传, 如果不开启则退出重传。
			 * 向前重传是重传从标记为丢失的最高序列号的skb到最高被sack过的skb.
			 *
			 * 满足以下所有条件开启向前重传：
			 * 1. 处于recovery状态
			 * 2. 启用sack
			 * 3. 无法发送新数据(无新数据/nagle限制/接收窗口限制)
			 */
			tp->retransmit_high = last_lost;
			if (!tcp_can_forward_retransmit(sk)) /* 判断当前拥塞状态和拥塞算法能否向前重传，不能的话就退出 */
				break;
			/* Backtrack if necessary to non-L'ed skb */
			if (hole != NULL) {
				skb = hole;
				hole = NULL;
			}
			fwd_rexmitting = 1; /* 开启向前重传 */
			goto begin_fwd;

		} else if (!(sacked & TCPCB_LOST)) { /* 不是丢失包 */
			if (hole == NULL && !(sacked & (TCPCB_SACKED_RETRANS|TCPCB_SACKED_ACKED))) /* 没有重传也没有被SACK过 */
				hole = skb;
			continue;

		} else { /* 这里为标记为丢失的数据包 */
			last_lost = TCP_SKB_CB(skb)->end_seq;
			if (icsk->icsk_ca_state != TCP_CA_Loss)
				mib_idx = LINUX_MIB_TCPFASTRETRANS;
			else
				mib_idx = LINUX_MIB_TCPSLOWSTARTRETRANS;
		}

		/* 被SACK过和已经重传过的不再重传 */
		if (sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))
			continue;

		if (tcp_retransmit_skb(sk, skb)) /* 重传 */
			return;
		NET_INC_STATS_BH(sock_net(sk), mib_idx);

		/* 如果是快速恢复阶段, 增加发送包的个数 */
		if (inet_csk(sk)->icsk_ca_state == TCP_CA_Recovery)
			tp->prr_out += tcp_skb_pcount(skb);

		/* 如果重传的是第一个包，则重置重传定时器 */
		if (skb == tcp_write_queue_head(sk))
			inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
						  inet_csk(sk)->icsk_rto,
						  TCP_RTO_MAX);
	}
}

/* Send a fin.  The caller locks the socket for us.  This cannot be
 * allowed to fail queueing a FIN frame under any circumstances.
 */
void tcp_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = tcp_write_queue_tail(sk); /* 发送队列的最后一个数据包 */
	int mss_now;

	/* Optimization, tack on the FIN if we have a queue of
	 * unsent frames.  But be careful about outgoing SACKS
	 * and IP options.
	 */
	mss_now = tcp_current_mss(sk);

	/* 如果发送队列有数据，直接在最后一个数据包加上FIN标志，
	 * 否则新建一个FIN包并加入发送队列中
	 */
	if (tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	} else {
		/* Socket is locked, keep trying until memory is available. */
		for (;;) {
			skb = alloc_skb_fclone(MAX_TCP_HEADER,
					       sk->sk_allocation);
			if (skb)
				break;
			yield();
		}

		/* Reserve space for headers and prepare control bits. */
		skb_reserve(skb, MAX_TCP_HEADER);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPCB_FLAG_ACK | TCPCB_FLAG_FIN);
		tcp_queue_skb(sk, skb); /* 将FIN包插入发送队列 */
	}
	__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF); /* 尝试发送 */
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by RFC 2525, section 2.17.  -DaveM
 */
void tcp_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
			     TCPCB_FLAG_ACK | TCPCB_FLAG_RST);
	/* Send it off. */
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	if (tcp_transmit_skb(sk, skb, 0, priority))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);

	TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTRSTS);
}

/* Send a crossed SYN-ACK during socket establishment.
 * WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff *skb;

	skb = tcp_write_queue_head(sk);
	if (skb == NULL || !(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_SYN)) {
		printk(KERN_DEBUG "tcp_send_synack: wrong queue state\n");
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb = skb_copy(skb, GFP_ATOMIC);
			if (nskb == NULL)
				return -ENOMEM;
			tcp_unlink_write_queue(skb, sk);
			skb_header_release(nskb);
			__tcp_add_write_queue_head(sk, nskb);
			sk_wmem_free_skb(sk, skb);
			sk->sk_wmem_queued += nskb->truesize;
			sk_mem_charge(sk, nskb->truesize);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_ACK;
		TCP_ECN_send_synack(tcp_sk(sk), skb);
	}
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

/* Prepare a SYN-ACK. */
struct sk_buff *tcp_make_synack(struct sock *sk, struct dst_entry *dst,
				struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcphdr *th;
	int tcp_header_size;
	struct tcp_out_options opts;
	struct sk_buff *skb;
	struct tcp_md5sig_key *md5;
	__u8 *md5_hash_location;
	int mss;

	skb = sock_wmalloc(sk, MAX_TCP_HEADER + 15, 1, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* Reserve space for headers. */
	skb_reserve(skb, MAX_TCP_HEADER);

	skb_dst_set(skb, dst_clone(dst));

	mss = dst_metric(dst, RTAX_ADVMSS);
	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < mss)
		mss = tp->rx_opt.user_mss;

	/* 这里计算初始接收窗口 */
	if (req->rcv_wnd == 0) { /* ignored for retransmitted syns */
		__u8 rcv_wscale;
		/* Set this up on the first call only */
		req->window_clamp = tp->window_clamp ? : dst_metric(dst, RTAX_WINDOW);
		/* tcp_full_space because it is guaranteed to be the first packet */
		tcp_select_initial_window(tcp_full_space(sk),
			mss - (ireq->tstamp_ok ? TCPOLEN_TSTAMP_ALIGNED : 0),
			&req->rcv_wnd,
			&req->window_clamp,
			ireq->wscale_ok,
			&rcv_wscale);
		ireq->rcv_wscale = rcv_wscale;
	}

	memset(&opts, 0, sizeof(opts));
#ifdef CONFIG_SYN_COOKIES
	/* 如果syncookie且支持timestamp则在timestamp中携带TCP选项 */
	if (unlikely(req->cookie_ts))
		TCP_SKB_CB(skb)->when = cookie_init_timestamp(req);
	else
#endif
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	tcp_header_size = tcp_synack_options(sk, req, mss,
					     skb, &opts, &md5) +
			  sizeof(struct tcphdr);

	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	th = tcp_hdr(skb);
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	TCP_ECN_make_synack(req, th);
	th->source = ireq->loc_port;
	th->dest = ireq->rmt_port;
	/* Setting of flags are superfluous here for callers (and ECE is
	 * not even correctly set)
	 */
	tcp_init_nondata_skb(skb, tcp_rsk(req)->snt_isn,
			     TCPCB_FLAG_SYN | TCPCB_FLAG_ACK);
	th->seq = htonl(TCP_SKB_CB(skb)->seq);
	th->ack_seq = htonl(tcp_rsk(req)->rcv_isn + 1);

	/* RFC1323: The window in SYN & SYN/ACK segments is never scaled. */
	th->window = htons(min(req->rcv_wnd, 65535U));
	tcp_options_write((__be32 *)(th + 1), tp, &opts, &md5_hash_location);
	th->doff = (tcp_header_size >> 2);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTSEGS);

#ifdef CONFIG_TCP_MD5SIG
	/* Okay, we have all we need - do the md5 hash if needed */
	if (md5) {
		tcp_rsk(req)->af_specific->calc_md5_hash(md5_hash_location,
					       md5, NULL, req, skb);
	}
#endif

	return skb;
}

/* Do all connect socket setups that can be done AF independent. */
static void tcp_connect_init(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr) +
		(sysctl_tcp_timestamps ? TCPOLEN_TSTAMP_ALIGNED : 0);

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk) != NULL)
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_mtup_init(sk);
	tcp_sync_mss(sk, dst_mtu(dst));

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = dst_metric(dst, RTAX_ADVMSS);
	if (tp->rx_opt.user_mss && tp->rx_opt.user_mss < tp->advmss)
		tp->advmss = tp->rx_opt.user_mss;

	tcp_initialize_rcv_mss(sk);

	tcp_select_initial_window(tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sysctl_tcp_window_scaling,
				  &rcv_wscale);

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, 0);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	tp->rcv_nxt = 0;
	tp->rcv_wup = 0;
	tp->copied_seq = 0;

	inet_csk(sk)->icsk_rto = TCP_TIMEOUT_INIT;
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);
}

/* Build a SYN and send it off. */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	tcp_connect_init(sk);

	buff = alloc_skb_fclone(MAX_TCP_HEADER + 15, sk->sk_allocation);
	if (unlikely(buff == NULL))
		return -ENOBUFS;

	/* Reserve space for headers. */
	skb_reserve(buff, MAX_TCP_HEADER);

	tp->snd_nxt = tp->write_seq;
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPCB_FLAG_SYN);
	TCP_ECN_send_syn(sk, buff);

	/* Send it off. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	tp->retrans_stamp = TCP_SKB_CB(buff)->when;
	skb_header_release(buff);
	__tcp_add_write_queue_tail(sk, buff);
	sk->sk_wmem_queued += buff->truesize;
	sk_mem_charge(sk, buff->truesize);
	tp->packets_out += tcp_skb_pcount(buff);
	err = tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	/* We change tp->snd_nxt after the tcp_transmit_skb() call
	 * in order to make this packet get counted in tcpOutSegs.
	 */
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int ato = icsk->icsk_ack.ato;
	unsigned long timeout;

	/* 设置ato的上限可能为： 
	 * 1. 500ms 
	 * 2. 200ms，如果处于延迟确认模式，或者处于快速确认模式且收到过小包 
	 * 3. RTT，如果有RTT采样 
	 */
	if (ato > TCP_DELACK_MIN) {
		const struct tcp_sock *tp = tcp_sk(sk);
		int max_ato = HZ / 2; /* 500ms */

		/* 如果处于延迟确认模式，或者处于快速确认模式且设置了ICSK_ACK_PUSHED标志 */
		if (icsk->icsk_ack.pingpong ||
		    (icsk->icsk_ack.pending & ICSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX; /* 200ms */

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use inet_csk(sk)->icsk_rto here, use results of rtt measurements
		 * directly.
		 */
		/* 如果有RTT采样，使用RTT来作为ato的最大值 */
		if (tp->srtt) {
			int rtt = max(tp->srtt >> 3, TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato); /* ato不能超过最大值 */
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato; /* 延迟ACK的超时时刻 */

	/* Use new timeout only if there wasn't a older one earlier. */
	/* 如果之前已经启动了延迟确认定时器了 */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		/* 如果之前延迟确认定时器触发时，因为socket被用户进程锁住而无法发送ACK，那么现在马上发送。 
		 * 或者如果接收到数据报时，延迟确认定时器已经快要超时了(离现在不到1/4 * ato)，那么马上发送ACK。 
		 */
		if (icsk->icsk_ack.blocked ||
		    time_before_eq(icsk->icsk_ack.timeout, jiffies + (ato >> 2))) {
			tcp_send_ack(sk);
			return;
		}

		/* 如果新的超时时间，比之前设定的超时时间晚，那么使用之前设定的超时时间 */
		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
	/* 如果还没有启动延迟确认定时器 */
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER; /* 设置ACK需要发送标志、定时器启动标志 */
	icsk->icsk_ack.timeout = timeout; /* 超时时间 */
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout); /* 启动延迟确认定时器 */
}

/* This routine sends an ack and also updates the window. */
void tcp_send_ack(struct sock *sk)
{
	struct sk_buff *buff;

	/* If we have been reset, we may not send again. */
	if (sk->sk_state == TCP_CLOSE)
		return;

	/* We are not putting this on the write queue, so
	 * tcp_transmit_skb() will set the ownership to this
	 * sock.
	 */
	buff = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (buff == NULL) { /* 分配skb失败 */
		inet_csk_schedule_ack(sk); /* 设置标志位，表示有ACK需要发送 */
		inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN; /* 重置ATO */
		/* 设置延迟确认定时器，超时时间为200ms */
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
					  TCP_DELACK_MAX, TCP_RTO_MAX);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(buff, MAX_TCP_HEADER); /* 设置报文头部的空间 */
	/* 初始化不携带数据的skb的一些控制字段 */
	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPCB_FLAG_ACK);

	/* Send it off, this clears delayed acks for us. */
	TCP_SKB_CB(buff)->when = tcp_time_stamp;
	tcp_transmit_skb(sk, buff, 0, GFP_ATOMIC);
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (skb == NULL)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPCB_FLAG_ACK);
	TCP_SKB_CB(skb)->when = tcp_time_stamp;
	return tcp_transmit_skb(sk, skb, 0, GFP_ATOMIC);
}

/* Initiate keepalive or window probe from timer. */
/* 发送0窗口持续探测段 或者 keepalive探测
 * 返回值：0表示发送成功；
 * 	   小于0表示发送失败; 
 * 	   大于0表示由于本地拥塞导致发送失败
 * */
int tcp_write_wakeup(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE)
		return -1;

	/* 如果发送队列有待发送数据，并且待发送数据有部分在接收窗口内，
	 * 则可以直接利用该待发送数据发送探测
	 */
	if ((skb = tcp_send_head(sk)) != NULL &&
	    before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = tcp_current_mss(sk);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		/* 确保只发出一个段且不超过MSS */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
			if (tcp_fragment(sk, skb, seg_size, mss))
				return -1;
		} else if (!tcp_skb_pcount(skb))
			tcp_set_skb_tso_segs(sk, skb, mss);

		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
		TCP_SKB_CB(skb)->when = tcp_time_stamp;
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_event_new_data_sent(sk, skb);
		return err;
	} else { /* 如果发送队列为空或超出接收窗口，则构造并发送一个已确认、长度为0的段给对端 
		  * 如果处理紧急模式，则多发送一个序号为snd.una的段给对端
		  */
		if (between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			tcp_xmit_probe_skb(sk, 1);
		return tcp_xmit_probe_skb(sk, 0);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
void tcp_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err;

	err = tcp_write_wakeup(sk); /* 发送0窗口持续探测段 */

	if (tp->packets_out || !tcp_send_head(sk)) { /* 如果网络上有数据或没数据待发送，则清零 */
		/* Cancel probe timer, if it is not required. */
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		return;
	}

	if (err <= 0) { /* 发送成功(0)，或并非由本地拥塞引起的发送失败(<0) */
		if (icsk->icsk_backoff < sysctl_tcp_retries2)
			icsk->icsk_backoff++; /* 增加指数退避 */
		icsk->icsk_probes_out++; /* 增加探测次数 */
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff, TCP_RTO_MAX),
					  TCP_RTO_MAX); /* 再次激活0窗口定时器 */
	} else { /* 如果由于本地拥塞导致的发送失败 */
		/* If packet was not sent due to local congestion,
		 * do not backoff and do not remember icsk_probes_out.
		 * Let local senders to fight for local resources.
		 *
		 * Use accumulated backoff yet.
		 */
		if (!icsk->icsk_probes_out)
			icsk->icsk_probes_out = 1;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_PROBE0,
					  min(icsk->icsk_rto << icsk->icsk_backoff,
					      TCP_RESOURCE_PROBE_INTERVAL), /* 缩短时间 */
					  TCP_RTO_MAX);
	}
}

EXPORT_SYMBOL(tcp_select_initial_window);
EXPORT_SYMBOL(tcp_connect);
EXPORT_SYMBOL(tcp_make_synack);
EXPORT_SYMBOL(tcp_simple_retransmit);
EXPORT_SYMBOL(tcp_sync_mss);
EXPORT_SYMBOL(tcp_mtup_init);
