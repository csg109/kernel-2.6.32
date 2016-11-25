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
/* rate_sample�ṹ����include/net/tcp.h�ж���: */

/* A rate sample measures the number of (original/retransmitted) data
 * packets delivered "delivered" over an interval of time "interval_us".
 * The tcp_rate.c code fills in the rate sample, and congestion
 * control modules that define a cong_control function to run at the end
 * of ACK processing can optionally chose to consult this sample when
 * setting cwnd and pacing rate.
 * A sample is invalid if "delivered" or "interval_us" is negative.
 */
/* ��delivered��interval_usΪ��ֵʱ��ʾ�ýṹ��Ч */
struct rate_sample {
	struct	skb_mstamp prior_mstamp; /* starting timestamp for interval */
				/* ȷ��������ʼʱ�� */
	u32  prior_delivered;	/* tp->delivered at "prior_mstamp" */
				/* ������ʼʱ���delivered, ���ڼ������ڵĽ����� */
	s32  delivered;		/* number of packets delivered over interval */
				/* ���ڽ�����,�����ڽ��������ݰ�����, 
				 * ����ACKȷ��ʱ��delivered�����ݰ�����ʱ��delivered(��prior_delivered)֮��õ�
				 */
	long interval_us;	/* time for tp->delivered to incr "delivered" */
				/* ���� = max(��������, ȷ������), ��λΪus */
	long rtt_us;		/* RTT of last (S)ACKed packet (or -1) */
				/* �ɼ���RTT(������������ݰ���ȡ,���ṩ��ӵ���㷨��RTT), ��λ΢�� */
	int  losses;		/* number of packets marked lost upon ACK */
				/* ͨ����ACK�жϳ������Ӷ����ĸ��� */
	u32  acked_sacked;	/* number of packets newly (S)ACKed upon ACK */
				/* ��ACKȷ��(delivered)�����ݰ����� */
	u32  prior_in_flight;	/* in flight before this ACK */
				/* ACK����ǰ��inflight */
	bool is_app_limited;	/* is sample from packet with bubble in pipe? */
				/* ACKȷ�ϵ����ݰ�����ʱ�Ƿ��ܵ�Ӧ�ò������ */
	bool is_retrans;	/* is sample from retransmission? */
				/* ACKȷ�ϵ����ݰ��Ƿ��ش��� */
};


struct tcp_sock�����ӵı���:

	/* ��0˵����ʱ�յ�Ӧ�ò����ݵ�����,���ݰ�û���������� */
	u32	app_limited;	/* limited until "delivered" reaches this val */

	/* �������������ֱ����ڼ��㷢�����ں�ȷ������,
	 * �������ڼ�����һ�����ݰ��ķ�����ֹ�����,
	 * ȷ�����ڼ�����һ�����ݰ���ȷ����ֹ�����.
	 *
	 * Ϊ�˱������ڵķ��ͻ�ȷ��ͻȻ����������ʵ����ֵ,
	 * ���յĵ�����Ϊ���ߴ��һ����
	 * ���� = max(��������, ȷ������)
	 */
	struct skb_mstamp first_tx_mstamp;  /* start of window send phase */
					    /* ��¼�������ڵ�һ�����ݰ���ʱ���
					     * ���ڼ��㷢������,������һ��RTT�����ݰ���ʱ��
					     */
	struct skb_mstamp delivered_mstamp; /* time we reached "delivered" */
					    /* ��¼�������(ACK/SACK)��ʱ���
					     * ���ڼ���ȷ������,��ȷ��һ��RTT�����ݰ���ʱ��
					     */

	/* ���������ֶ������ṩ�����Ĵ����getsockopt, ���㷨���� */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */

#endif //0

/* Snapshot the current delivery information in the skb, to generate
 * a rate sample later when the skb is (s)acked in tcp_rate_skb_delivered().
 */
/* ���ݰ�����ʱ��¼delivered�Լ��������ں�ȷ�����ڵ���Ӧʱ���,
 * ��tcp_transmit_skb()�е��� 
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
	 /* ��һ�����ݰ�, ���г�ʼ�� */
	if (!tp->packets_out) {
		tp->first_tx_mstamp  = skb->skb_mstamp;
		tp->delivered_mstamp = skb->skb_mstamp;
	}

	/* ��ֵ��ʱ�������ڵ���ʼʱ��, ���������ݰ�ȷ��ʱ�����뱾���ݰ�����ʱ��ʱ���ֵ������������� */
	TCP_SKB_CB(skb)->tx.first_tx_mstamp	= tp->first_tx_mstamp;
	/* ��ֵ��ʱȷ�����ڵ���ʼʱ��, ���������ݰ�ȷ��ʱ������ȷ��ʱ��ʱ���ֵ�����ȷ������ */
	TCP_SKB_CB(skb)->tx.delivered_mstamp	= tp->delivered_mstamp;
	/* ��¼��ʱ��delivered, ���������ݰ�ȷ��ʱ������ȷ��ʱ��delivered��ֵ���㽻���������� */
	TCP_SKB_CB(skb)->tx.delivered		= tp->delivered;
	/* ��¼��ʱ�Ƿ��ܵ�Ӧ�ò�û�����ݵ����� */
	TCP_SKB_CB(skb)->tx.is_app_limited	= tp->app_limited ? 1 : 0;
}

/* When an skb is sacked or acked, we fill in the rate sample with the (prior)
 * delivery information when the skb was last transmitted.
 *
 * If an ACK (s)acks multiple skbs (e.g., stretched-acks), this function is
 * called multiple times. We favor the information from the most recently
 * sent skb, i.e., the skb with the highest prior_delivered count.
 */
/* �����ݰ�ȷ��ʱ(ACK��SACK)������ȡ֮ǰ����ʱ�������Ϣ,
 * ���ڼ��㷢�����ڡ�ȷ�����ںͽ�����
 */
void tcp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb,
			    struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *scb = TCP_SKB_CB(skb);

	/* ������ݰ�֮ǰ��SACK��,����SACKʱ�Ѿ���ȡ����Ϣ,��ʱ���� */
	if (!scb->tx.delivered_mstamp.v64)
		return;

	/* ���ݸ�ACKȷ�ϵ����һ�����ݰ���ȡ��Ϣ */
	if (!rs->prior_delivered ||
	    after(scb->tx.delivered, rs->prior_delivered)) {
		rs->prior_delivered  = scb->tx.delivered; /* ��¼��ʱ��deliveredֵ */
		rs->prior_mstamp     = scb->tx.delivered_mstamp; /* ��¼��ʱ��ȷ����ʼʱ���, 
								  * ������tcp_rate_gen()�ټ���ȷ������ 
								  */
		rs->is_app_limited   = scb->tx.is_app_limited; /* ��ʱ�Ƿ��ܵ�Ӧ�ò����� */
		rs->is_retrans	     = scb->sacked & TCPCB_RETRANS; /* �Ƿ��ش��� */

		/* Find the duration of the "send phase" of this window: */
		/* ���㷢������, �������ݰ����͵�ʱ���������ڵ�һ�����ݰ�����ʱ�������õ�
		 * ����interval_us�ȱ���Ϊ��������,֮����tcp_rate_gen()�л����ȷ�����ڲ�ȡ����С��
		 */
		rs->interval_us      = skb_mstamp_us_delta(
						&skb->skb_mstamp,
						&scb->tx.first_tx_mstamp);

		/* Record send time of most recently ACKed packet: */
		/* ��������������ʼʱ���, �������ݰ��Ը����ݰ�����ʱ��Ϊ����������ʼ�� */
		tp->first_tx_mstamp  = skb->skb_mstamp;
	}
	/* Mark off the skb delivered once it's sacked to avoid being
	 * used again when it's cumulatively acked. For acked packets
	 * we don't need to reset since it'll be freed soon.
	 */
	/* ��������ݰ��Ǳ�SACK��,Ϊ�˱������ACK�ۻ�ȷ��ʱ�ظ�����,����delivered_mstamp */
	if (scb->sacked & TCPCB_SACKED_ACKED)
		scb->tx.delivered_mstamp.v64 = 0;
}

/* Update the connection delivery information and generate a rate sample. */
/* ����������յ�rate_sample�ṹ, �ṩ��ӵ���㷨,�������ڡ����ڵĽ�������.
 * @delivered: ��ACKȷ��(ack/sack)���������ݰ�����
 * @lost: ͨ����ACK���ӵĶ�ʧ���ݰ�����
 * @now: ��ǰʱ���
 */
void tcp_rate_gen(struct sock *sk, u32 delivered, u32 lost,
		  struct skb_mstamp *now, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 snd_us, ack_us;

	/* Clear app limited if bubble is acked and gone. */
	/* �����ǰ�յ�Ӧ�ò������,
 	 * �������յ����һ���ܵ�Ӧ�ò����Ƶ����ݰ�����һ�����ݰ���ACK
	 * �ͱ���Ӧ�ò����ƽ��
	 */
	if (tp->app_limited && after(tp->delivered, tp->app_limited))
		tp->app_limited = 0;

	/* TODO: there are multiple places throughout tcp_ack() to get
	 * current time. Refactor the code using a new "tcp_acktag_state"
	 * to carry current time, flags, stats like "tcp_sacktag_state".
	 */
	/* �����ACK��ȷ������,�����ȷ��������ʼ��,
	 * �������͵����ݰ�ȷ��ʱ�Ե�ǰΪȷ��������ʼ��
	 */
	if (delivered)
		tp->delivered_mstamp = *now;

	/* ��¼���������ݰ����� */
	rs->acked_sacked = delivered;	/* freshly ACKed or SACKed */
	/* ��¼�����Ķ�ʧ���ݰ����� */
	rs->losses = lost;		/* freshly marked lost */
	/* Return an invalid sample if no timing information is available. */
	/* ���prior_mstampΪ0,˵��û�л�ȡ����Ϣ, rate_sample��Ч, ���� */
	if (!rs->prior_mstamp.v64) {
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}
	/* ��������ڵĽ�������, ����ǰ��������ȥ������ʼ�Ľ����� */
	rs->delivered   = tp->delivered - rs->prior_delivered;

	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 */
	/* interval_us֮ǰ��tcp_rate_skb_delivered()���Ѿ���ֵΪ����ķ������� */
	snd_us = rs->interval_us;				/* send phase */
	/* �������ȷ������, ����ǰʱ���ȥȷ��������ʼʱ�� */
	ack_us = skb_mstamp_us_delta(now, &rs->prior_mstamp);	/* ack phase */
	/* ���յ�����ȡ�������ں�ȷ�����ڴ��, ���ص�Ŀ���Ƿ�ֹͻȻ������������̫С�õ�����Ĵ���ֵ */
	rs->interval_us = max(snd_us, ack_us);

	/* Normally we expect interval_us >= min-rtt.
	 * Note that rate may still be over-estimated when a spuriously
	 * retransmistted skb was first (s)acked because "interval_us"
	 * is under-estimated (up to an RTT). However continuously
	 * measuring the delivery rate during loss recovery is crucial
	 * for connections suffer heavy or prolonged losses.
	 */
	/* �����������С����СRTTҲ��Ϊ������Ч */
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
	/* ��¼����õ��Ĵ�����յ�Ӧ�ò�����ʱ��������
	 * ��Ҫ�ṩ��getsockopt, ���㷨����
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
/* ��Ӧ�ò㷢�͵�ʱ��(tcp_sendmsg()/tcp_sendpage())�жϴ�ʱ�Ƿ��ܵ�Ӧ�ò�û�����ݵ�����,
 * ��Ϊ��ʱ������������������ǲ�׼ȷ��, ������Ҫ��־
 * ֱ�������յ����һ���ܵ�Ӧ�ò����Ƶ����ݰ�����һ�����ݰ���ACK�ű���Ӧ�ò����ƽ��
 */
void tcp_rate_check_app_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* ��������4������˵����ʱ�ܵ�Ӧ�ò����ݵ����� */
	if (/* We have less than one packet to send. */
	    /* TCP���Ͷ���������һ��MSS��δ�������� */
	    tp->write_seq - tp->snd_nxt < tp->mss_cache &&
	    /* Nothing in sending host's qdisc queues or NIC tx queue. */
	    /* ���Ͷ���ߵĶ���û�����ݰ�δ���ͣ�����fq���������Ͷ��� */
	    sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) &&
	    /* We are not limited by CWND. */
	    /* ���Ͷ�û���ܵ�ӵ�����ڵ����� */
	    tcp_packets_in_flight(tp) < tp->snd_cwnd &&
	    /* All lost packets have been retransmitted. */
	    /* û�н�Ҫ�ش��ı��Ϊ��ʧ�����ݰ� */
	    tp->lost_out <= tp->retrans_out)
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
}
