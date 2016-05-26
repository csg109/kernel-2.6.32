/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __cpu_to_be32(0x00800000),
	TCP_FLAG_ECE = __cpu_to_be32(0x00400000),
	TCP_FLAG_URG = __cpu_to_be32(0x00200000),
	TCP_FLAG_ACK = __cpu_to_be32(0x00100000),
	TCP_FLAG_PSH = __cpu_to_be32(0x00080000),
	TCP_FLAG_RST = __cpu_to_be32(0x00040000),
	TCP_FLAG_SYN = __cpu_to_be32(0x00020000),
	TCP_FLAG_FIN = __cpu_to_be32(0x00010000),
	TCP_RESERVED_BITS = __cpu_to_be32(0x0F000000),
	TCP_DATA_OFFSET = __cpu_to_be32(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */
#define TCP_THIN_LINEAR_TIMEOUTS 16      /* Use linear timeouts for thin streams*/
#define TCP_THIN_DUPACK         17      /* Fast retrans. after 1 dupack */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block { /* ��ʾһ��SACK�� */
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
				/* ��¼��ʱ��(get_seconds()�ķ���ֵ) 
				 * ��ts_recent��Ӧ��ʱ��,��λΪ��
				 */
	u32	ts_recent;	/* Time stamp to echo next		*/
				/* ���һ���յ��Է���ʱ���, ��rcv_tsval */
	u32	rcv_tsval;	/* Time stamp value             	*/
				/* �յ���ʱ���ֵ(�Է���ʱ���) */
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
				/* �յ���ʱ�������Ӧ��(�Է��ظ�����ԭ����ʱ���) */
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
				/* �������ݰ����յ���ʱ��� */
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
				/* �յ�SYN��ʱ����ֵΪsaw_tstamp, ��ʾsyn��������ʱ��� 
				 * ���������жϸ������Ƿ�������ʱ���
				 */
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
				/* �����˴����������� */
		sack_ok : 4,	/* SACK seen on SYN packet		*/
				/* ������SACK */
				/* ��һλΪSACK��־,�ڶ�λΪFACK��־������λΪD-SACK��־ */
		snd_wscale : 4,	/* Window scaling received from sender	*/
				/* syn���յ��Ĵ����������ӣ����Ϊ14 */
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl */
				/* �û����õ����MSS */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
				/* syn���յ���MSS��С, �����user_mss������Ϊuser_mss*/
};

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increse this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	const struct tcp_request_sock_ops *af_specific;
#endif
	u32			 	rcv_isn;	/* �ͻ��˵ĳ�ʼ���к� */
	u32			 	snt_isn;	/* ���˵ĳ�ʼ���к� */
	u32				snt_synack; /* synack sent time *//* ��һ��synack�ظ���ʱ�������������RTT */
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/
	u16	xmit_size_goal_segs; /* Goal for segmenting output packets */

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
 	u32	rcv_nxt;	/* What we want to receive next 	*//* �ڴ����յ���һ�������ֽڵ����к� */
	u32	copied_seq;	/* Head of yet unread data		*//* ��û�б���ȡ�����ݵ����к�, Ӧ�ó����´δ����︴������ */
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*//* �����һ�δ���update������֮ǰ��rcv_nxt */
 	u32	snd_nxt;	/* Next sequence we send		*//* ��һ��Ҫ���͵����к� */

 	u32	snd_una;	/* First byte we want an ack for	*//* ��һ��Ҫ��ACK�����к� */
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) *//* ���һ�ν��յ�ack��ʱ�������Ҫ����keepalive */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) *//* ���һ�η������ݰ���ʱ��� */

	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue;
		struct task_struct	*task;
		struct iovec		*iov;
		int			memory;
		int			len;
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	/* snd_wll ��¼���ʹ��ڸ���ʱ����ɴ��ڸ��µ��Ǹ����ݱ��ĵ�һ����š� 
 	 * ����Ҫ��������һ���ж��Ƿ���Ҫ���·��ʹ��ڡ� 
         */	
	u32	snd_wl1;	/* Sequence for window update		*/
	/* ���ʹ��ڵĴ�С��ֱ��ȡֵ�����ԶԷ������ݱ���TCP�ײ� */
	u32	snd_wnd;	/* The window we expect to receive	*/
	/* ��¼���ԶԷ�ͨ��Ĵ��ڵ����ֵ */
	u32	max_window;	/* Maximal window ever seen from peer	*/
	/* ���ͷ���ǰ��ЧMSS */
	u32	mss_cache;	/* Cached effective mss, not including SACKS */
	/* ���մ��ڵ�����ֵ��һ��Ϊ(65535U << wscale)����TCP�ײ��ܱ�ʾ�������մ��� */	
	u32	window_clamp;	/* Maximal window to advertise		*/
	/* ���մ�����ֵ, ������̬���ƽ��մ��ڵ����� */
	u32	rcv_ssthresh;	/* Current window clamp			*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u16	advmss;		/* Advertised MSS			*/ /* ���ն�ͨ���MSS */
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle;	/* Disable Nagle algorithm?             */

/* RTT measurement */
	/* ƽ����RTT��Ϊ���⸡�����㣬�ǽ���Ŵ�8����洢�� */
	u32	srtt;		/* smoothed round trip time << 3	*/
	/* RTT��ƽ��ƫ�Խ��˵��RTT����Խ���� */
	u32	mdev;		/* medium deviation			*/
	/* ����ÿ�η��������ڵĶα�ȫ��ȷ�Ϲ����У�RTTƽ��ƫ������ֵ */
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	/* ƽ����RTTƽ��ƫ���mdev�õ�����������RTO */
	u32	rttvar;		/* smoothed mdev_max			*/
	/* ��¼SND.UNA */
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	/* �ӷ��Ͷ��з�����δ�õ�ȷ�ϵ�TCP����Ŀ����SND.NXT-SND.UNA */
	u32	packets_out;	/* Packets which are "in flight"	*/
	/* �ش���δ�õ�ȷ�ϵĵ�TCP����Ŀ */
	u32	retrans_out;	/* Retransmitted packets out		*/

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	reordering;	/* Packet reordering metric.		*/
	u32	snd_up;		/* Urgent pointer		*/

	u8	keepalive_probes; /* num of allowed keep alive probes	*/
				  /* ��setsockopt���õ�keepalive��̽����� */
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*//* ��������ֵ */
 	u32	snd_cwnd;	/* Sending congestion window		*//* ӵ������ */
	/* ��ʾ�ڵ�ǰ��ӵ�����ƴ������Ѿ����͵����ݶεĸ���,
	 * ���Դ��ϴε���ӵ�����ڵ�ĿǰΪֹ���յ����ܵ�ACK������
	 * ���snd_cwnd_cntΪ0����˵���Ѿ�������ӵ�����ڣ��ҵ�Ŀǰ��δ�յ�ACK�Ρ�
	 */
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this *//* �����ӵ���������ֵ */
	u32	snd_cwnd_used;	/* ÿ�η������¼packets_out���������cwnd��û�б���ȫʹ�� */
	u32	snd_cwnd_stamp; /* ÿ�θı�ӵ�����ڼ�¼ʱ��� */

 	u32	rcv_wnd;	/* Current receiver window		*//* ���մ��ڴ�С */
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer *//* ���ͻ����β��seq, ��Ӧ�ò��ύ���ں˵�β��seq */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*//* ��ʧ������Ŀ */
	/* ����SACKʱ����ʶ�ѽ��յ��ε�����
	 * ������SACKʱ����ʶ���յ��ظ�ȷ�ϵĴ��� 
	 */
	u32	sacked_out;	/* SACK'd packets			*/
	/* ��¼SND.UNA��SACKѡ����Ŀǰ���շ��յ��Ķ��������Ŷ�֮��Ķ��� */
	u32	fackets_out;	/* FACK'd packets			*/
	u32	tso_deferred;
	/* ����tcp_abc����ӵ������׶α�����ȷ�ϵ��ֽ��� */
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	/* from STCP, retrans queue hinting */
	struct sk_buff *lost_skb_hint; 		/* ���ش������У������´�Ҫ��־�ĶΣ�Ϊ�˼��ٶ��ش����еı�־���� */
	struct sk_buff *scoreboard_skb_hint;	/* ��¼��ʱ�����ݰ��������� */
	struct sk_buff *retransmit_skb_hint; 	/* ��ʾ��Ҫ�ش�����ʼ�� */

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */
						/* ������У���ʱ�洢�����skb */

	/* SACKs data, these 2 need to be together (see tcp_build_and_update_options) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4]; /* �����յ���SACK�飬�������Ч�� */

	struct sk_buff *highest_sack;   /* highest skb with SACK received
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */
					/* sack���������skb����һ��, û��SACK��ʱָ���ش����еĵ�һ�����ݰ� */

	int     lost_cnt_hint;		/* �Ѿ���־�˶��ٸ��� */
	u32     retransmit_high;	/* L-bits may be on up to this seqno */
					/* ��Ҫ�ش���������к� */

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */
					/* ��¼��һ���ش�����snd_nxt, ���ش�����Ӧ����Сsnd_nxt */

	/* ��¼������ٻָ�����������ֵ�����ڳ������� */
	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	/* ��¼����ӵ��ʱ��SND.NXT,��ʶ�ش����е�β�� */
	u32	high_seq;	/* snd_nxt at onset of congestion	*//* ��¼ӵ������ʱ��snd_nxt */

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
				/* ���һ���ش���ʼ��ʱ��� */
	/* ��ʹ��F-RTO�㷨���з��ͳ�ʱ���������Recovery�����ش��������Loss��ʼ������ʱ��
	 * ��¼��ʱ��SND.UNA,����ش���ʼ�㡣
	 * ���Ǽ���Ƿ���Խ���ӵ������������֮һ��һ�������ӵ���������������Loss״̬������
	 */
	u32	undo_marker;	/* tracking retrans started here. */
	/* �����ж��ܷ����ӵ�������ı���,
	 * �ش����ݰ���ʱ������Ӹ�ֵ
	 * ���յ�D-SACKʱ(�ж�Ϊ����Ҫ���ش�)����ٸ�ֵ 
	 * �����ֵΪ0˵���ش������ݰ�����D-SACK�ˣ������ǲ���Ҫ���ش���
	 * ����Գ�����ӵ�����ڵĵ���
	 */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
						  /* ��setsockopt���õ�keepalive̽��ʱ��,�����ж�ú�ŷ���̽�ⱨ�� */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
						  /* ��setsockopt���õ�keepalive��̽����, ��̽�ⱨ��֮���ʱ���� */

	int			linger2;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;	/* ���ն˹��Ƶ�RTT */
		u32	seq;	/* ���ڼ�¼һ��RTT��β�����к�, ����rcv_wndΪһ��RTT */
		u32	time; 	/* ��¼ʱ��������ڼ���RTT */
	} rcv_rtt_est; /* ���ڽ��ն˵�RTT���� */

/* Receiver queue space */
	struct {
		int	space; 	/* ��ʾ��ǰ���ջ���Ĵ�С��ֻ����Ӧ�ò����ݣ���λΪ�ֽڣ� */
		u32	seq;	/* ��¼ÿ�ε���ʱ��copied_seq */
		u32	time;	/* ��¼ʱ��� */
	} rcvq_space; /* ���ڵ������ջ������ͽ��մ��� */

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif

#ifndef __GENKSYMS__
	u8	thin_lto    : 1,/* Use linear timeouts for thin streams */
		thin_dupack : 1,/* Fast retransmit on first dupack      */
		unused      : 6;

	u32	prior_cwnd;	/* Congestion window at start of Recovery. */
				/* ����Recoveryʱ��ӵ������ */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
				/* ʵ��������ͳ�ƿ��ٻָ���ACKȷ�ϵĶ������������뿪������ٶȡ� */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */
				/* ��¼���ٻָ��׶η��͵����ݰ�����, ʵ��������ͳ��sending_rate�����ݽ���������ٶ� */
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
