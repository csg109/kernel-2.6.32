#include <net/tcp.h>

/* The bandwidth estimator estimates the rate at which the network
 * can currently deliver outbound data packets for this flow. At a high
 * level, it operates by taking a delivery rate sample for each ACK.
 *
 * A rate sample records the rate at which the network delivered packets
 * for this flow, calculated over the time interval between the transmission
 * of a data packet and the acknowledgment of that packet.
 *
 * Specifically, over the interval between each transmit and corresponding ACK,
 * the estimator generates a delivery rate sample. Typically it uses the rate
 * at which packets were acknowledged. However, the approach of using only the
 * acknowledgment rate faces a challenge under the prevalent ACK decimation or
 * compression: packets can temporarily appear to be delivered much quicker
 * than the bottleneck rate. Since it is physically impossible to do that in a
 * sustained fashion, when the estimator notices that the ACK rate is faster
 * than the transmit rate, it uses the latter:
 *
 *    send_rate = #pkts_delivered/(last_snd_time - first_snd_time)
 *    ack_rate  = #pkts_delivered/(last_ack_time - first_ack_time)
 *    bw = min(send_rate, ack_rate)
 *
 * Notice the estimator essentially estimates the goodput, not always the
 * network bottleneck link rate when the sending or receiving is limited by
 * other factors like applications or receiver window limits.  The estimator
 * deliberately avoids using the inter-packet spacing approach because that
 * approach requires a large number of samples and sophisticated filtering.
 *
 * TCP flows can often be application-limited in request/response workloads.
 * The estimator marks a bandwidth sample as application-limited if there
 * was some moment during the sampled window of packets when there was no data
 * ready to send in the write queue.
 */


#if 0
/* rate_sample结构体在include/net/tcp.h中定义: */

/* A rate sample measures the number of (original/retransmitted) data
 * packets delivered "delivered" over an interval of time "interval_us".
 * The tcp_rate.c code fills in the rate sample, and congestion
 * control modules that define a cong_control function to run at the end
 * of ACK processing can optionally chose to consult this sample when
 * setting cwnd and pacing rate.
 * A sample is invalid if "delivered" or "interval_us" is negative.
 */
/* 当delivered或interval_us为负值时表示该结构无效 */
struct rate_sample {
	struct	skb_mstamp prior_mstamp; /* starting timestamp for interval */
				/* 确认周期起始时间 */
	u32  prior_delivered;	/* tp->delivered at "prior_mstamp" */
				/* 周期起始时间的delivered, 用于计算周期的交付量 */
	s32  delivered;		/* number of packets delivered over interval */
				/* 周期交付量,即周期交付的数据包个数, 
				 * 根据ACK确认时的delivered与数据包发送时的delivered(即prior_delivered)之差得到
				 */
	long interval_us;	/* time for tp->delivered to incr "delivered" */
				/* 周期 = max(发送周期, 确认周期), 单位为us */
	long rtt_us;		/* RTT of last (S)ACKed packet (or -1) */
				/* 采集的RTT(根据最近的数据包获取,即提供给拥塞算法的RTT), 单位微秒 */
	int  losses;		/* number of packets marked lost upon ACK */
				/* 通过该ACK判断出新增加丢包的个数 */
	u32  acked_sacked;	/* number of packets newly (S)ACKed upon ACK */
				/* 该ACK确认(delivered)的数据包个数 */
	u32  prior_in_flight;	/* in flight before this ACK */
				/* ACK处理前的inflight */
	bool is_app_limited;	/* is sample from packet with bubble in pipe? */
				/* ACK确认的数据包发送时是否受到应用层的限制 */
	bool is_retrans;	/* is sample from retransmission? */
				/* ACK确认的数据包是否被重传过 */
};


struct tcp_sock里增加的变量:

	/* 非0说明此时收到应用层数据的限制,数据包没有填满带宽 */
	u32	app_limited;	/* limited until "delivered" reaches this val */

	/* 以下两个变量分别用于计算发送周期和确认周期,
	 * 发送周期即根据一轮数据包的发送起止点计算,
	 * 确认周期即根据一轮数据包的确认起止点计算.
	 *
	 * 为了避免周期的发送或确认突然抖动超过真实带宽值,
	 * 最终的的周期为两者大的一个：
	 * 周期 = max(发送周期, 确认周期)
	 */
	struct skb_mstamp first_tx_mstamp;  /* start of window send phase */
					    /* 记录发送周期第一个数据包的时间戳
					     * 用于计算发送周期,即发送一轮RTT的数据包的时间
					     */
	struct skb_mstamp delivered_mstamp; /* time we reached "delivered" */
					    /* 记录最近交付(ACK/SACK)的时间戳
					     * 用于计算确认周期,即确认一轮RTT的数据包的时间
					     */

	/* 以下两个字段用于提供测量的带宽给getsockopt, 非算法本身 */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */

#endif //0

/* Snapshot the current delivery information in the skb, to generate
 * a rate sample later when the skb is (s)acked in tcp_rate_skb_delivered().
 */
/* 数据包发送时记录delivered以及发送周期和确认周期的相应时间戳,
 * 在tcp_transmit_skb()中调用 
 */
void tcp_rate_skb_sent(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	 /* In general we need to start delivery rate samples from the
	  * time we received the most recent ACK, to ensure we include
	  * the full time the network needs to deliver all in-flight
	  * packets. If there are no packets in flight yet, then we
	  * know that any ACKs after now indicate that the network was
	  * able to deliver those packets completely in the sampling
	  * interval between now and the next ACK.
	  *
	  * Note that we use packets_out instead of tcp_packets_in_flight(tp)
	  * because the latter is a guess based on RTO and loss-marking
	  * heuristics. We don't want spurious RTOs or loss markings to cause
	  * a spuriously small time interval, causing a spuriously high
	  * bandwidth estimate.
	  */
	 /* 第一个数据包, 进行初始化 */
	if (!tp->packets_out) {
		tp->first_tx_mstamp  = skb->skb_mstamp;
		tp->delivered_mstamp = skb->skb_mstamp;
	}

	/* 赋值此时发送周期的起始时间, 后续在数据包确认时根据与本数据包发送时的时间差值计算出发送周期 */
	TCP_SKB_CB(skb)->tx.first_tx_mstamp	= tp->first_tx_mstamp;
	/* 赋值此时确认周期的起始时间, 后续在数据包确认时根据与确认时的时间差值计算出确认周期 */
	TCP_SKB_CB(skb)->tx.delivered_mstamp	= tp->delivered_mstamp;
	/* 记录此时的delivered, 后续在数据包确认时根据与确认时的delivered差值计算交付的数据量 */
	TCP_SKB_CB(skb)->tx.delivered		= tp->delivered;
	/* 记录此时是否受到应用层没有数据的限制 */
	TCP_SKB_CB(skb)->tx.is_app_limited	= tp->app_limited ? 1 : 0;
}

/* When an skb is sacked or acked, we fill in the rate sample with the (prior)
 * delivery information when the skb was last transmitted.
 *
 * If an ACK (s)acks multiple skbs (e.g., stretched-acks), this function is
 * called multiple times. We favor the information from the most recently
 * sent skb, i.e., the skb with the highest prior_delivered count.
 */
/* 在数据包确认时(ACK或SACK)根据提取之前发送时保存的信息,
 * 用于计算发送周期、确认周期和交付量
 */
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
			    struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

	/* 如果数据包之前被SACK过,则在SACK时已经获取过信息,此时跳过 */
	if (!scb->tx.delivered_mstamp.v64)
		return;

	/* 根据该ACK确认的最后一个数据包获取信息 */
	if (!rs->prior_delivered ||
	    after(scb->tx.delivered, rs->prior_delivered)) {
		rs->prior_delivered  = scb->tx.delivered; /* 记录当时的delivered值 */
		rs->prior_mstamp     = scb->tx.delivered_mstamp; /* 记录当时的确认起始时间戳, 
								  * 后面在tcp_rate_gen()再计算确认周期 
								  */
		rs->is_app_limited   = scb->tx.is_app_limited; /* 当时是否受到应用层限制 */
		rs->is_retrans	     = scb->sacked & TCPCB_RETRANS; /* 是否重传过 */

		/* Find the duration of the "send phase" of this window: */
		/* 计算发送周期, 根据数据包发送的时间戳与该周期第一个数据包发送时间戳相减得到
		 * 这里interval_us先保存为发送周期,之后在tcp_rate_gen()中会计算确认周期并取两者小的
		 */
		rs->interval_us      = skb_mstamp_us_delta(
						&skb->skb_mstamp,
						&scb->tx.first_tx_mstamp);

		/* Record send time of most recently ACKed packet: */
		/* 调整发送周期起始时间戳, 后续数据包以该数据包发送时间为发送周期起始点 */
		tp->first_tx_mstamp  = skb->skb_mstamp;
	}
	/* Mark off the skb delivered once it's sacked to avoid being
	 * used again when it's cumulatively acked. For acked packets
	 * we don't need to reset since it'll be freed soon.
	 */
	/* 如果该数据包是被SACK的,为了避免后续ACK累积确认时重复计算,清零delivered_mstamp */
	if (scb->sacked & TCPCB_SACKED_ACKED)
		scb->tx.delivered_mstamp.v64 = 0;
}

/* Update the connection delivery information and generate a rate sample. */
/* 计算填充最终的rate_sample结构, 提供给拥塞算法,包括周期、周期的交付量等.
 * @delivered: 该ACK确认(ack/sack)交付的数据包个数
 * @lost: 通过该ACK增加的丢失数据包个数
 * @now: 当前时间戳
 */
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
		  struct skb_mstamp *now, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 snd_us, ack_us;

	/* Clear app limited if bubble is acked and gone. */
	/* 如果此前收到应用层的限制,
 	 * 当我们收到最后一个受到应用层限制的数据包的下一个数据包的ACK
	 * 就表明应用层限制解除
	 */
	if (tp->app_limited && after(tp->delivered, tp->app_limited))
		tp->app_limited = 0;

	/* TODO: there are multiple places throughout tcp_ack() to get
	 * current time. Refactor the code using a new "tcp_acktag_state"
	 * to carry current time, flags, stats like "tcp_sacktag_state".
	 */
	/* 如果该ACK有确认数据,则更新确认周期起始点,
	 * 后续发送的数据包确认时以当前为确认周期起始点
	 */
	if (delivered)
		tp->delivered_mstamp = *now;

	/* 记录交付的数据包个数 */
	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	/* 记录新增的丢失数据包个数 */
	rs->losses = lost;		/* freshly marked lost */
	/* Return an invalid sample if no timing information is available. */
	/* 如果prior_mstamp为0,说明没有获取到信息, rate_sample无效, 返回 */
	if (!rs->prior_mstamp.v64) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}
	/* 计算该周期的交付数据, 即当前交付量减去周期起始的交付量 */
	rs->delivered   = tp->delivered - rs->prior_delivered;

	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 */
	/* interval_us之前在tcp_rate_skb_delivered()中已经赋值为计算的发送周期 */
	snd_us = rs->interval_us;				/* send phase */
	/* 这里计算确认周期, 即当前时间减去确认周期起始时间 */
	ack_us = skb_mstamp_us_delta(now, &rs->prior_mstamp);	/* ack phase */
	/* 最终的周期取发送周期和确认周期大的, 保守点目的是防止突然抖动导致周期太小得到过大的带宽值 */
	rs->interval_us = max(snd_us, ack_us);

	/* Normally we expect interval_us >= min-rtt.
	 * Note that rate may still be over-estimated when a spuriously
	 * retransmistted skb was first (s)acked because "interval_us"
	 * is under-estimated (up to an RTT). However continuously
	 * measuring the delivery rate during loss recovery is crucial
	 * for connections suffer heavy or prolonged losses.
	 */
	/* 当计算的周期小于最小RTT也认为数据无效 */
	if (unlikely(rs->interval_us < tcp_min_rtt(tp))) {
		if (!rs->is_retrans)
			pr_debug("tcp rate: %ld %d %u %u %u\n",
				 rs->interval_us, rs->delivered,
				 inet_csk(sk)->icsk_ca_state,
				 tp->rx_opt.sack_ok, tcp_min_rtt(tp));
		rs->interval_us = -1;
		return;
	}

	/* Record the last non-app-limited or the highest app-limited bw */
	/* 记录最近得到的带宽或收到应用层限制时的最大带宽
	 * 主要提供给getsockopt, 非算法本身
	 */
	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tp->rate_delivered = rs->delivered;
		tp->rate_interval_us = rs->interval_us;
		tp->rate_app_limited = rs->is_app_limited;
	}
}

/* If a gap is detected between sends, mark the socket application-limited. */
/* 在应用层发送的时候(tcp_sendmsg()/tcp_sendpage())判断此时是否受到应用层没有数据的限制,
 * 因为此时数据少用来计算带宽是不准确的, 所以需要标志
 * 直到我们收到最后一个受到应用层限制的数据包的下一个数据包的ACK才表明应用层限制解除
 */
void tcp_rate_check_app_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* 满足以下4个条件说明此时受到应用层数据的限制 */
	if (/* We have less than one packet to send. */
	    /* TCP发送队列中少于一个MSS的未发送数据 */
	    tp->write_seq - tp->snd_nxt < tp->mss_cache &&
	    /* Nothing in sending host's qdisc queues or NIC tx queue. */
	    /* 发送端这边的队列没有数据包未发送，比如fq和网卡发送队列 */
	    sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) &&
	    /* We are not limited by CWND. */
	    /* 发送端没有受到拥塞窗口的限制 */
	    tcp_packets_in_flight(tp) < tp->snd_cwnd &&
	    /* All lost packets have been retransmitted. */
	    /* 没有将要重传的标记为丢失的数据包 */
	    tp->lost_out <= tp->retrans_out)
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
}
