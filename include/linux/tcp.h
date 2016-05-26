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

struct tcp_sack_block { /* 表示一个SACK块 */
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
				/* 记录秒时间(get_seconds()的返回值) 
				 * 即ts_recent对应的时间,单位为秒
				 */
	u32	ts_recent;	/* Time stamp to echo next		*/
				/* 最后一次收到对方的时间戳, 即rcv_tsval */
	u32	rcv_tsval;	/* Time stamp value             	*/
				/* 收到的时间戳值(对方的时间戳) */
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/
				/* 收到的时间戳回显应答(对方回复本方原来的时间戳) */
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/
				/* 最后的数据包接收到了时间戳 */
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/
				/* 收到SYN包时被赋值为saw_tstamp, 表示syn包开启了时间戳 
				 * 后续用来判断该连接是否启用了时间戳
				 */
		dsack : 1,	/* D-SACK is scheduled			*/
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/
				/* 开启了窗口扩大因子 */
		sack_ok : 4,	/* SACK seen on SYN packet		*/
				/* 开启了SACK */
				/* 第一位为SACK标志,第二位为FACK标志，第三位为D-SACK标志 */
		snd_wscale : 4,	/* Window scaling received from sender	*/
				/* syn包收到的窗口扩大因子，最大为14 */
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/
/*	SACKs data	*/
	u8	num_sacks;	/* Number of SACK blocks		*/
	u16	user_mss;  	/* mss requested by user in ioctl */
				/* 用户设置的最大MSS */
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
				/* syn包收到的MSS大小, 如果比user_mss大，则置为user_mss*/
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
	u32			 	rcv_isn;	/* 客户端的初始序列号 */
	u32			 	snt_isn;	/* 本端的初始序列号 */
	u32				snt_synack; /* synack sent time *//* 第一个synack回复的时间戳，用来计算RTT */
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
 	u32	rcv_nxt;	/* What we want to receive next 	*//* 期待接收的下一个数据字节的序列号 */
	u32	copied_seq;	/* Head of yet unread data		*//* 还没有被读取的数据的序列号, 应用程序下次从这里复制数据 */
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*//* 当最后一次窗口update被发送之前的rcv_nxt */
 	u32	snd_nxt;	/* Next sequence we send		*//* 下一个要发送的序列号 */

 	u32	snd_una;	/* First byte we want an ack for	*//* 下一个要被ACK的序列号 */
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) *//* 最后一次接收到ack的时间戳，主要用于keepalive */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) *//* 最后一次发送数据包的时间戳 */

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

	/* snd_wll 记录发送窗口更新时，造成窗口更新的那个数据报的第一个序号。 
 	 * 它主要用于在下一次判断是否需要更新发送窗口。 
         */	
	u32	snd_wl1;	/* Sequence for window update		*/
	/* 发送窗口的大小，直接取值于来自对方的数据报的TCP首部 */
	u32	snd_wnd;	/* The window we expect to receive	*/
	/* 记录来自对方通告的窗口的最大值 */
	u32	max_window;	/* Maximal window ever seen from peer	*/
	/* 发送方当前有效MSS */
	u32	mss_cache;	/* Cached effective mss, not including SACKS */
	/* 接收窗口的上限值，一般为(65535U << wscale)，即TCP首部能表示的最大接收窗口 */	
	u32	window_clamp;	/* Maximal window to advertise		*/
	/* 接收窗口阈值, 用来动态控制接收窗口的增长 */
	u32	rcv_ssthresh;	/* Current window clamp			*/

	u32	frto_highmark;	/* snd_nxt when RTO occurred */
	u16	advmss;		/* Advertised MSS			*/ /* 接收端通告的MSS */
	u8	frto_counter;	/* Number of new acks after RTO */
	u8	nonagle;	/* Disable Nagle algorithm?             */

/* RTT measurement */
	/* 平滑的RTT，为避免浮点运算，是将其放大8倍后存储的 */
	u32	srtt;		/* smoothed round trip time << 3	*/
	/* RTT的平均偏差，越大说明RTT抖动越厉害 */
	u32	mdev;		/* medium deviation			*/
	/* 跟踪每次发动窗口内的段被全部确认过程中，RTT平均偏差的最大值 */
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/
	/* 平滑的RTT平均偏差，由mdev得到，用来计算RTO */
	u32	rttvar;		/* smoothed mdev_max			*/
	/* 记录SND.UNA */
	u32	rtt_seq;	/* sequence number to update rttvar	*/

	/* 从发送队列发出而未得到确认的TCP段数目，即SND.NXT-SND.UNA */
	u32	packets_out;	/* Packets which are "in flight"	*/
	/* 重传还未得到确认的的TCP段数目 */
	u32	retrans_out;	/* Retransmitted packets out		*/

	u16	urg_data;	/* Saved octet of OOB data and control flags */
	u8	ecn_flags;	/* ECN status bits.			*/
	u8	reordering;	/* Packet reordering metric.		*/
	u32	snd_up;		/* Urgent pointer		*/

	u8	keepalive_probes; /* num of allowed keep alive probes	*/
				  /* 由setsockopt设置的keepalive的探测次数 */
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*//* 慢启动阈值 */
 	u32	snd_cwnd;	/* Sending congestion window		*//* 拥塞窗口 */
	/* 表示在当前的拥塞控制窗口中已经发送的数据段的个数,
	 * 即自从上次调整拥塞窗口到目前为止接收到的总的ACK段数。
	 * 如果snd_cwnd_cnt为0，则说明已经调整了拥塞窗口，且到目前还未收到ACK段。
	 */
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this *//* 允许的拥塞窗口最大值 */
	u32	snd_cwnd_used;	/* 每次发包后记录packets_out，用来检测cwnd有没有被完全使用 */
	u32	snd_cwnd_stamp; /* 每次改变拥塞窗口记录时间戳 */

 	u32	rcv_wnd;	/* Current receiver window		*//* 接收窗口大小 */
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer *//* 发送缓存的尾部seq, 即应用层提交给内核的尾部seq */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*//* 丢失包的数目 */
	/* 启动SACK时，标识已接收到段的数量
	 * 不启用SACK时，标识接收到重复确认的次数 
	 */
	u32	sacked_out;	/* SACK'd packets			*/
	/* 记录SND.UNA与SACK选项中目前接收方收到的段中最高序号段之间的段数 */
	u32	fackets_out;	/* FACK'd packets			*/
	u32	tso_deferred;
	/* 启动tcp_abc后，在拥塞避免阶段保存已确认的字节数 */
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */

	/* from STCP, retrans queue hinting */
	struct sk_buff *lost_skb_hint; 		/* 在重传队列中，缓存下次要标志的段，为了加速对重传队列的标志操作 */
	struct sk_buff *scoreboard_skb_hint;	/* 记录超时的数据包，序号最大 */
	struct sk_buff *retransmit_skb_hint; 	/* 表示将要重传的起始包 */

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */
						/* 乱序队列，暂时存储乱序的skb */

	/* SACKs data, these 2 need to be together (see tcp_build_and_update_options) */
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

	struct tcp_sack_block recv_sack_cache[4]; /* 保存收到的SACK块，用于提高效率 */

	struct sk_buff *highest_sack;   /* highest skb with SACK received
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */
					/* sack处理的最大的skb的下一个, 没有SACK块时指向重传队列的第一个数据包 */

	int     lost_cnt_hint;		/* 已经标志了多少个段 */
	u32     retransmit_high;	/* L-bits may be on up to this seqno */
					/* 需要重传的最高序列号 */

	u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */
					/* 记录第一个重传包的snd_nxt, 即重传包对应的最小snd_nxt */

	/* 记录进入快速恢复的慢启动阈值，用于撤销窗口 */
	u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
	/* 记录发生拥塞时的SND.NXT,标识重传队列的尾部 */
	u32	high_seq;	/* snd_nxt at onset of congestion	*//* 记录拥塞发生时的snd_nxt */

	u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
				/* 最后一次重传开始的时间戳 */
	/* 在使用F-RTO算法进行发送超时处理，或进入Recovery进行重传，或进入Loss开始慢启动时，
	 * 记录当时的SND.UNA,标记重传起始点。
	 * 它是检测是否可以进行拥塞撤销的条件之一，一般在完成拥塞撤销操作或进入Loss状态后清零
	 */
	u32	undo_marker;	/* tracking retrans started here. */
	/* 用于判断能否进行拥塞撤销的变量,
	 * 重传数据包的时候会增加该值
	 * 在收到D-SACK时(判断为不必要的重传)会减少该值 
	 * 如果该值为0说明重传的数据包都被D-SACK了，即都是不必要的重传，
	 * 则可以撤销对拥塞窗口的调整
	 */
	int	undo_retrans;	/* number of undoable retransmissions. */
	u32	total_retrans;	/* Total retransmits for entire connection */

	u32	urg_seq;	/* Seq of received urgent pointer */
	unsigned int		keepalive_time;	  /* time before keep alive takes place */
						  /* 由setsockopt设置的keepalive探测时间,即空闲多久后才发送探测报文 */
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */
						  /* 由setsockopt设置的keepalive的探测间隔, 即探测报文之间的时间间隔 */

	int			linger2;

/* Receiver side RTT estimation */
	struct {
		u32	rtt;	/* 接收端估计的RTT */
		u32	seq;	/* 用于记录一个RTT结尾的序列号, 接收rcv_wnd为一个RTT */
		u32	time; 	/* 记录时间戳，用于计算RTT */
	} rcv_rtt_est; /* 用于接收端的RTT测量 */

/* Receiver queue space */
	struct {
		int	space; 	/* 表示当前接收缓存的大小（只包括应用层数据，单位为字节） */
		u32	seq;	/* 记录每次调整时的copied_seq */
		u32	time;	/* 记录时间戳 */
	} rcvq_space; /* 用于调整接收缓冲区和接收窗口 */

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
				/* 进入Recovery时的拥塞窗口 */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
				/* 实际上用于统计快速恢复中ACK确认的段数，即数据离开网络的速度。 */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */
				/* 记录快速恢复阶段发送的数据包个数, 实际上用于统计sending_rate，数据进入网络的速度 */
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
