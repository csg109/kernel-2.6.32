/*
 * TCP Vegas congestion control interface
 */
#ifndef __TCP_VEGAS_H
#define __TCP_VEGAS_H 1

/* Vegas variables */
struct vegas {
	u32	beg_snd_nxt;	/* right edge during last RTT */
	u32	beg_snd_una;	/* left edge  during last RTT */
	u32	beg_snd_cwnd;	/* saves the size of the cwnd *//* 没有使用，直接用snd_cwnd代替 */
	u8	doing_vegas_now;/* if true, do vegas for this RTT *//* 决定是否使用Vegas */
	u16	cntRTT;		/* # of RTTs measured within last RTT *//* 每收到一个ACK就可以得到一个RTT样本，
				 * 这个RTT内所收到的ACK的个数，就是所能得到的上个RTT的样本数*/
	u32	minRTT;		/* min of RTTs measured within last RTT (in usec) *//* 取cntRTT个样本 
	                   	 * 中的最小者作为上个RTT的测量值，这样可以避免delayed ack的干扰*/
	u32	baseRTT;	/* the min of all Vegas RTT measurements seen (in usec) *//* 本连接的 
	                	 * 最小RTT, 实时更新。表示路由中没有缓存本连接数据包时的RTT，用于计算理想吞吐量*/
};

extern void tcp_vegas_init(struct sock *sk);
extern void tcp_vegas_state(struct sock *sk, u8 ca_state);
extern void tcp_vegas_pkts_acked(struct sock *sk, u32 cnt, s32 rtt_us);
extern void tcp_vegas_cwnd_event(struct sock *sk, enum tcp_ca_event event);
extern void tcp_vegas_get_info(struct sock *sk, u32 ext, struct sk_buff *skb);

#endif	/* __TCP_VEGAS_H */
