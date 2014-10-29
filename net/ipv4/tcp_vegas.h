/*
 * TCP Vegas congestion control interface
 */
#ifndef __TCP_VEGAS_H
#define __TCP_VEGAS_H 1

/* Vegas variables */
struct vegas {
	u32	beg_snd_nxt;	/* right edge during last RTT */
	u32	beg_snd_una;	/* left edge  during last RTT */
	u32	beg_snd_cwnd;	/* saves the size of the cwnd *//* û��ʹ�ã�ֱ����snd_cwnd���� */
	u8	doing_vegas_now;/* if true, do vegas for this RTT *//* �����Ƿ�ʹ��Vegas */
	u16	cntRTT;		/* # of RTTs measured within last RTT *//* ÿ�յ�һ��ACK�Ϳ��Եõ�һ��RTT������
				 * ���RTT�����յ���ACK�ĸ������������ܵõ����ϸ�RTT��������*/
	u32	minRTT;		/* min of RTTs measured within last RTT (in usec) *//* ȡcntRTT������ 
	                   	 * �е���С����Ϊ�ϸ�RTT�Ĳ���ֵ���������Ա���delayed ack�ĸ���*/
	u32	baseRTT;	/* the min of all Vegas RTT measurements seen (in usec) *//* �����ӵ� 
	                	 * ��СRTT, ʵʱ���¡���ʾ·����û�л��汾�������ݰ�ʱ��RTT�����ڼ�������������*/
};

extern void tcp_vegas_init(struct sock *sk);
extern void tcp_vegas_state(struct sock *sk, u8 ca_state);
extern void tcp_vegas_pkts_acked(struct sock *sk, u32 cnt, s32 rtt_us);
extern void tcp_vegas_cwnd_event(struct sock *sk, enum tcp_ca_event event);
extern void tcp_vegas_get_info(struct sock *sk, u32 ext, struct sk_buff *skb);

#endif	/* __TCP_VEGAS_H */
