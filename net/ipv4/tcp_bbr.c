/* Bottleneck Bandwidth and RTT (BBR) congestion control
 *
 * BBR congestion control computes the sending rate based on the delivery
 * rate (throughput) estimated from ACKs. In a nutshell:
 *
 *   On each ACK, update our model of the network path:
 *      bottleneck_bandwidth = windowed_max(delivered / elapsed, 10 round trips)
 *      min_rtt = windowed_min(rtt, 10 seconds)
 *   pacing_rate = pacing_gain * bottleneck_bandwidth
 *   cwnd = max(cwnd_gain * bottleneck_bandwidth * min_rtt, 4)
 *
 * The core algorithm does not react directly to packet losses or delays,
 * although BBR may adjust the size of next send per ACK when loss is
 * observed, or adjust the sending rate if it estimates there is a
 * traffic policer, in order to keep the drop rate reasonable.
 *
 * BBR is described in detail in:
 *   "BBR: Congestion-Based Congestion Control",
 *   Neal Cardwell, Yuchung Cheng, C. Stephen Gunn, Soheil Hassas Yeganeh,
 *   Van Jacobson. ACM Queue, Vol. 14 No. 5, September-October 2016.
 *
 * There is a public e-mail list for discussing BBR development and testing:
 *   https://groups.google.com/forum/#!forum/bbr-dev
 *
 * NOTE: BBR *must* be used with the fq qdisc ("man tc-fq") with pacing enabled,
 * since pacing is integral to the BBR design and implementation.
 * BBR without pacing would not function properly, and may incur unnecessary
 * high packet loss rates.
 */
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>
#include <linux/inet.h>
#include <linux/random.h>
#include <linux/win_minmax.h>

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */
#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE) /* �������ʱ����ĵ�λ */

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode { /* BBR��ģʽ */
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
			/* ���ӿ�ʼʱ����̽�����, �൱��������,
			 * ֱ����Ϊ��������ʱ��������DRAINģʽ
			 */
	BBR_DRAIN,	/* drain any queue created during startup */
			/* DRAINģʽĿ�������֮ǰSTARTUPģʽ���۵��ŶӶ��� 
			 * ֱ���ŶӶ��е����ݰ���ȫ������˳�DRAINģʽ����PROBE_BWģʽ
			 */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
			/* PROBE_BWģʽ���ص��ǽ�һ��ʱ��ֳ�8��ʱ��Ƭ��Ȼ��˳��ѭ���ؽ���:
			 * a.���ӷ������ʣ�pacing_gain = 1.25����̽�����1��ʱ��Ƭ����
			 * b.���ͷ������ʣ�pacing_gain = 0.75��������ŶӶ��У�1��ʱ��Ƭ����
			 * c.ά�ַ������ʲ��䣨pacing_gain =1����������ô�����������ŶӶ��У�6��ʱ��Ƭ��
			 */
	BBR_PROBE_RTT,	/* cut cwnd to min to probe min_rtt */
			/* PROBE_RTTģʽ������min_rtt��ʱδ���£�10��δ���£�ʱ�������ʹ�����̽��RTT��
			 * ����PROBE_RTTģʽ�󣬻Ὣcwnd����Ϊ������4��������·�������������ݰ�����ȡ׼ȷ��min_rtt��
			 * PROBE_RTTģʽ��ȵ�inflight<=4��ά��max(200 ms, 1 round)��ʱ��Ȼ���˳�PROBE_RTTģʽ�ָ�֮ǰ��ģʽ��
			 * �ڵʹ���ά������һ��RTT���ڱ�֤�ܲɼ���min_rtt��
			 * �κ�ģʽ�¶����ܽ���PROBE_RTTģʽ��
			 * �����˳�PROBE_RTTģʽ��᷵��֮ǰ��ģʽ��cwndҲ��ָ�֮ǰ��С��
			 */
};

/* BBR congestion control block */
struct bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
					/* ����10�봰�ڹ��˵���СRTT, ��λ΢�� */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
					/* ��¼min_rtt_usʱ��ʱ���, �����ж�min_rtt_us���� */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
				        /* �˳�PROBE_RTTģʽ��ʱ���, ��inflight<=4�����200ms��ʱ�� */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
				/* �������, ��λΪ pkts/us << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
				    /* ��¼�ڼ���RTT����, ���ڹ����������Ĵ��ڹ��� */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
				    /* ��¼ÿ��RTT������ʼʱtp->delivered, �����ж�ÿ��RTT���ڽ��� */
	struct skb_mstamp cycle_mstamp;  /* time of this cycle phase start */
					 /* PROBE_BWģʽ�м�¼pacing rata������������bbr_pacing_gain�л�ʱ�����ʱ�� */
	u32     mode:3,		     /* current bbr_mode in state machine */
				     /* ��ǰBBRģʽ, ��enum bbr_mode���� */
		prev_ca_state:3,     /* CA state on previous ACK */
				     /* ��һ��ACK��ӵ��״̬ */
		packet_conservation:1,  /* use packet conservation? */
				     /* ����ģʽ: �ս�����ٻָ��ĵ�һ��RTT������ʹ�ñ���ģʽ, �յ�P������ȷ�Ϸ���P���� */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
				     /* ������Ҫ�ָ����붪��״̬(recovery/loss)��ӵ������ */
		round_start:1,	     /* start of packet-timed tx->ack round? */
				     /* ��ʾ��ǰ�Ǳ���RTT���ڵ���ʼ */
		tso_segs_goal:7,     /* segments we want in each skb we send */
				     /* TSOÿ���ֶεİ�����, �Ǹ���pacing rate����ÿms�������õ� */
		idle_restart:1,	     /* restarting after idle? */
				     /* ��Ǹմ�idle(Ӧ�ò�������)�ָ���ʼ�������� */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
					 /* PROBE_RTTģʽ�����ڱ�Ǿ�����һ��RTT���� */
		unused:5,	     /* δʹ�� */
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
				     /* �Ƿ����LT�ɼ�(���ֶ�����ſ�ʼ) */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
				     /* ��¼LT�ɼ�����(���Ѿ�ȷ��ʹ��LT)�ĵڼ���RTT���� */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
				     /* ��־�Ƿ�ʹ��LT���ٴ���, ���Ѿ�ȷ��Ϊ�������� */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
				     /* LT���ٴ���, ����LT���������ڵĽ����������ڼ��� */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
			     	     /* LT�ɼ�������ʼ��delivered, �������ڽ�������㽻���� */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
				     /* LT�ɼ�������ʼ��ʱ��, �������ڽ������������ʱ�䳤�� */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
				     /* LT�ɼ�������ʼ�Ķ�����, ���ڼ��������ڵĶ����� */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
				/* ��ǰpacing rate����������
				 * STARTUPģʽΪbbr_high_gain(2.885)
				 * DRAINģʽΪbbr_drain_gain(0.336)
				 * PROBE_BWģʽ�Ƕ�̬������,����ʱ��Ƭ��bbr_pacing_gain������ѯ
				 * PROBE_RTTģʽΪBBR_UNIT(1)
				 * LT(long-term��������)ΪBBR_UNIT(1)
				 */
		cwnd_gain:10,	/* current gain for setting cwnd */
				/* ��ǰcwnd����������
				 * STARTUPģʽΪbbr_high_gain(2.885)
				 * DRAINģʽΪbbr_high_gain(2.885)
				 * PROBE_BWģʽΪbbr_cwnd_gain(2)
				 * PROBE_RTTģʽΪBBR_UNIT(1)
				 * LT(long-term��������)ά�ֶ�Ӧģʽ�µ�ֵ
				 */
		full_bw_cnt:3,	/* number of rounds without large bw gains */
				/* ��ʾ�Ѿ������������ڹ������û��������, �����жϴ������� */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
				/* PROBE_BWģʽ�е�ǰpacing_gain��Ӧbbr_pacing_gain������±� */
		unused_b:6;	/* δʹ�� */
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
				/* ����(��һ��)����RECOVERY/LOSSʱ��cwnd, �Ա�undo */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */
				/* ��һ�����ڵĹ������, �����жϹ��������û������ */
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2; /* ������˴��ڳ���Ϊ10������ */
/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10; /* min_rtt���ڹ��˳�ȥ, 10�� */
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200; /* PROBE_RTTģʽά���ڵʹ������Сʱ�� */
/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000; /* ��150KB/S */

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
/* bbr_high_gainΪ����������������, ����Ϊ 2/ln2 = 2.885��, 
 * pacing rate��2/ln(2)�൱�ڴ�ͳ��������ÿ��RTT���ڷ���
 */
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1; /* ����Ϊ2.885�� */
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
/* DRAINģʽpacing rate������, Ϊ1/high_gain = 0.336 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885; /* Ϊ0.336�� */
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
/* PROBE_BWģʽcwnddeep������Ϊ2�� */
static const int bbr_cwnd_gain  = BBR_UNIT * 2; /* Ϊ2�� */

/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
/* PROBE_BWģʽ��һ��ʱ��ֳ�8��ʱ��Ƭ(ÿ��ʱ��Ƭ����Ϊmin_rtt)��Ȼ��˳��ѭ���ؽ��У�
 * 1.���ӷ������ʣ�pacing_gain = 1.25����̽�����1��ʱ��Ƭ����
 * 2.���ͷ������ʣ�pacing_gain = 0.75��������ŶӶ��У�1��ʱ��Ƭ����
 * 3.ά�ַ������ʲ��䣨pacing_gain =1����������ô�����������ŶӶ��У�6��ʱ��Ƭ����
 */
static const int bbr_pacing_gain[] = {
	/* 1��ʱ��Ƭ��1.25������, ̽����� */
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	/* 1��ʱ��Ƭ��0.75����С, ����ŶӶ��� */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	/* 6��ʱ��Ƭά�ִ�����, ������ô����������ŶӶ��� */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
/* ���ڽ���PROBE_BWģʽʱ���ѡ��pacing_gain�±� */
static const u32 bbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4; /* ӵ������/inflight��СֵΪ4 */

/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
/* ���STARTUPģʽ����3������������û�дﵽ25%, ����Ϊ�������� */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4; /* 125%, ��������25% */
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 bbr_full_bw_cnt = 3; /* ���3�������ڹ������û��������˵���������� */

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
/* ����LT��������ʱ�䳤�ȣ�
 * 	��Сbbr_lt_intvl_min_rtts ���4*bbr_lt_intvl_min_rtts, ��λΪRTT����
 * 	��[4 round, 16 round]
 */
static const u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
/* LT���ڲ�����ֵ������, ���������ڶ����ʳ���20%ʱ����Ϊ���ڽ���
 * ��������� ��ֵ������ = bbr_lt_loss_thresh / BBR_UNIT = 50 / 256 = 19.5%(���20%)
 */
static const u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
/* LT���ж������������ڴ���Ĳ�������С��(�����)1/8 ����Ϊ����������(�м��豸������������) */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
/* LT���ж������������ڴ���Ĳ�����ֵС��(�����)4KB/s ����Ϊ����������(�м��豸������������) */
static const u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
/* LT���ٴ���ʹ�õ����RTT������, ������ʹ��LTһ��ʱ����˳����� */
static const u32 bbr_lt_bw_max_rtts = 48;

/* Do we estimate that STARTUP filled the pipe? */
/* ���ش����Ƿ�����, �����������3�����ڹ������û������25%, ����Ϊ������ */
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_cnt >= bbr_full_bw_cnt;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
/* ���ؾ�����󴰿ڹ��˺�Ĺ������, ��λΪ pkts/us << BW_SCALE */
static u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
/* ���ع������, ��λΪ pkts/us << BW_SCALE */
static u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* ����ж�ΪLT��������, �򷵻����ٴ���,
	 * ���򷵻������Ĺ������
	 */
	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
/* ����λΪ(pkts/us << 24)�Ĵ���(��������)@rate����(@gain >> 8)������ת����bytes/sec��λ */
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)
{
	rate *= tcp_mss_to_mtu(sk, tcp_sk(sk)->mss_cache);
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}

/* Pace using current bw estimate and a gain factor. In order to help drive the
 * network toward lower queues while maintaining high utilization and low
 * latency, the average pacing rate aims to be slightly (~1%) lower than the
 * estimated bandwidth. This is an important aspect of the design. In this
 * implementation this slightly lower pacing rate is achieved implicitly by not
 * including link-layer headers in the packet size used for the pacing rate.
 */
/* ͨ������@bw�ͳ˷�����@gain����pacing rate 
 * ��������ע���ᵽ: 
 * 	���õ�pacing rate����С�ڴ���(bbr_update_bw()�м������pkts/usû������ȡ��)
 * 	����Ϊ���ǵ�pacing rate��û�а�����·ͷ�Ĵ�С(�����ϴ����Ҫ��1%)
 */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u64 rate = bw;

	/* ��ȡ����bw��gain��,��λΪbytes/sec */
	rate = bbr_rate_bytes_per_sec(sk, rate, gain); 
	/* ������������,Ӧ�ò�����,Ĭ��Ϊ���~0ֵ */
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	/* ����pacing rate, �������STARTUPģʽ��ֻ������ */
	if (bbr->mode != BBR_STARTUP || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

/* Return count of segments we want in the skbs we send, or 0 for default. */
/* ����ÿ��TSO�ֶε����ݰ�����, 0��ʾĬ�ϴ��� */
static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return bbr->tso_segs_goal;
}

/* ����pacing rate����TSOÿ���ֶεİ����� */
static void bbr_set_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 min_segs;

	/* ������СTSOÿ���ֶΰ�����: ���pacing rate��������С��150KB/S��Ϊ1, ����Ϊ2 */
	min_segs = sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
	/* ����TSOÿ���ֶεİ�����: tcp_tso_autosize������pacing rateת��Ϊÿms�İ���������
	 * ���ﻹ�������ֵ127
	 */
	bbr->tso_segs_goal = min(tcp_tso_autosize(sk, tp->mss_cache, min_segs),
				 0x7FU);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
/* ����cwnd, ����֮��ָ� */
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	/* ��һ�ν���RECOVERY/LOSS, ֱ�ӱ��洰��ֵ */
	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	/* ���״ν���RECOVERY/LOSS����PROBE_RTTģʽ, ȡ���ߴ�� */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tp->snd_cwnd);
}

/* ��Ҫ�����idle�ָ�����¼� */
static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	/* ֮ǰӦ�ò�������, �������¿�ʼ�������� */
	if (event == CA_EVENT_TX_START && tp->app_limited) {
		bbr->idle_restart = 1; /* ��־��idle�ָ� */
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		/* ��ʱ�������PROBE_BWģʽ, pacing rate��ʱ������,
		 * ��Ϊ��ʱ�մ�idle�ָ�������Ҫ��ô��, Ŀ����ʹpacing����ƽ��
		 */
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
	}
}

/* Find target cwnd. Right-size the cwnd based on min RTT and the
 * estimated bottleneck bandwidth:
 *
 * cwnd = bw * min_rtt * gain = BDP * gain
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 *
 * To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
/* ����Ŀ��ӵ�����ڴ�С
 * ���㷽ʽΪ: 
 * 	cwnd = bw * min_rtt * gain = BDP * gain, ��Ŀ��ӵ������ΪBDP��gain����
 */
static u32 bbr_target_cwnd(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	/* ����ʱû��min_rttֵʱ(�������ݰ������ش���),
	 * ��������´��ڿ��ܻᱻRTO����Ϊ1, �����������ǿ������������Ƚϰ�ȫ�Ĵ���: ��ʼ����
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * bbr->min_rtt_us; /*  ����BDP, ��λ�� ������<<BW_SCALE */

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	/* ����BDP��gain����, ������ȡ�� */
	cwnd = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	/* ������3��TSO�ֶ�, ���ǵ��ն˵Ļ���? */
	cwnd += 3 * bbr->tso_segs_goal;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	/* ���ǵ�delay-ack, ������1 */
	cwnd = (cwnd + 1) & ~1U;

	return cwnd; /* ����Ŀ��ӵ������ */
}

/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
/* ���ƶ���״̬(recovery/loss״̬)�µ�ӵ�����ڿ���ģʽ 
 * ����true��ʾ���ڱ���ģʽ
 */
static bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, u32 acked, u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = tp->snd_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	/* ����������µĶ���, �����ȰѴ��ڼ��������ĸ���
	 * �Ǳ���ģʽ��������bbr_set_cwnd()������������Ŀ�괰��
	 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	/* �ս���RECOVERY״̬, ��һ��RTT����ʹ�ñ���ģʽ: ÿ�յ�P������ȷ�Ϸ���P����, �������ݰ��غ� */
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		bbr->packet_conservation = 1; /* ��־����ģʽ */
		bbr->next_rtt_delivered = tp->delivered;  /* start round now *//* ��¼����ģʽ���,�����ж��˳�ʱ�� */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = tcp_packets_in_flight(tp) + acked; /* ����ģʽ�������ݰ��غ� */
	/* �մӶ����ָ�(LOSS��RECOVERY״̬)�˳� */
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		bbr->restore_cwnd = 1; /* ������Ҫ�������� */
		bbr->packet_conservation = 0; /* ȡ������ģʽ */
	}
	bbr->prev_ca_state = state; /* ��¼ӵ��״̬ */

	/* �Ӷ���״̬�ָ�ʱ����֮ǰӵ�����ڵļ�С, �ָ�Ϊ���붪��״̬��ӵ������ */
	if (bbr->restore_cwnd) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, bbr->prior_cwnd);
		bbr->restore_cwnd = 0;
	}

	/* ����ģʽ, �������ݰ��غ�: ȷ��P��������P���� */
	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
/* ӵ�����ڿ���:
 * 1.��������µĶ���, �򴰿����ȼ�ȥ��������: cwnd1 = cwnd - loss
 * 2.����ǽ���recovery�ĵ�һ��RTT����������ģʽ: 
 * 	���ְ��غ�, ȷ��P��������P����, cwnd = inflight + acked
 * 3.����ӵ������������Ŀ�괰��, ����Ϊ
 *   ����Ŀ�괰��(����ʱ�ӳ˻���gain��): 
 *       target_cwnd = BDP * gain = bw * rtt_min *gain
 *   a.�����ʱ��������(����3�����ڹ������û������): cwnd = min(cwnd1 + acked, target_cwnd)
 *   b.���С��Ŀ�괰��������������: cwnd = cwnd1 + acked
 *   c.���� cwnd = cwnd1
 */
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	/* ��ȷ�����ݰ�(ACK/SACK)������ */
	if (!acked)
		return;

	/* �ȴ�����״̬�µ�ӵ������, 
	 * ����true��ʾ���ڸս�����ٻָ��ı���ģʽ��, ��ʱ������ӵ������
	 */
	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	/* ��ȡĿ��ӵ������, ���С��Ŀ��ӵ�����������������Ӵ��� */
	target_cwnd = bbr_target_cwnd(sk, bw, gain); /* ��ȡĿ��ӵ������ */
	/* �������������(˵���Ѿ��˳�STARTUPģʽ), 
	 * ���������ӵ��������Ҫ����ΪĿ�괰�ڴ�С(��������ʱ����Ҳ���С)
	 */
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	/* ���������ǰӵ������С��Ŀ�괰��(�򻹴��ڵ�һ��������), ������������ */
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target); /* ӵ��������СֵΪ4 */

done:
	/* ����ӵ������ */
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
	/* �����PROBE_RTTģʽ, �����cwnd���ܳ���4�� */
	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
		tp->snd_cwnd = min(tp->snd_cwnd, bbr_cwnd_min_target);
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
/* �ж�PROBE_BW״̬���Ƿ���Ҫ�л�pacing rate������(pacing_gain) */
static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	/* �ж�ʱ��Ƭ�Ƿ���, һ��ʱ��ƬΪһ��min_rtt */
	bool is_full_length =
		skb_mstamp_us_delta(&tp->delivered_mstamp, &bbr->cycle_mstamp) >
		bbr->min_rtt_us;
	u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	/* pacing rate������Ϊ1.0ʱ(���������ֳ�����ô����������ŶӶ���),
	 * ʱ��Ƭ��ȫ�������л�������
	 */
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = rs->prior_in_flight;  /* what was in-flight before ACK? */
	bw = bbr_max_bw(sk);

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	/* ��pacing rate�������ʴ���1(��1.25), 
	 * ��Ҫ�ȵ�ʱ��Ƭ���� ���� �����˶�������inflight����(����1.25��BDP)���л�,
	 * ȷ��̽������Ч��
	 */
	if (bbr->pacing_gain > BBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= bbr_target_cwnd(sk, bw, bbr->pacing_gain));

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	/* ��pacing rate������С��1(��0.75),
	 * �ȵ�ʱ��Ƭ������inflightС��BDPʱ�л�
	 */
	return is_full_length ||
		inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
}

/* ѭ������pacing rate������: pacing_gain��������bbr_pacing_gain */
static void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1); /* ��ǰ�±�ѭ����1 */
	bbr->cycle_mstamp = tp->delivered_mstamp; /* ��¼�л�����ʼʱ�� */
	bbr->pacing_gain = bbr_pacing_gain[bbr->cycle_idx]; /* �л�pacing_gain */
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
/* ����PROBE_BWģʽpacing rate������(pacing_gain)���л� */
static void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* PROBE_BWģʽ�Ҳ������������Ʋ���(����������)ʱ, ����pacing rate�����ʵ��л� */
	if ((bbr->mode == BBR_PROBE_BW) && !bbr->lt_use_bw &&
	    bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk); /* ѭ���л�pacing rate������ */
}

/* ����ΪSTARTUPģʽ */
static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = bbr_high_gain;
	bbr->cwnd_gain	 = bbr_high_gain;
}

/* ����PROBE_BWģʽ */
static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW; /* �л�ΪPROBE_BWģʽ */
	bbr->pacing_gain = BBR_UNIT; /* ��������û����, ���ϱ�����bbr_advance_cycle_phase()���� */
	bbr->cwnd_gain = bbr_cwnd_gain; /* PROBE_BWģʽcwnd������Ϊ�̶���2�� */
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand); /* ���ѡ��bbr_pacing_gain�����±� */
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle *//* ����pacing rate������ */
}

/* ���ص�����PROBE_RTTģʽ֮ǰ��ģʽ
 * ����û����DRAINģʽ����Ϊ
 * 	PROBE_RTTģʽ���������ʹ�����ŶӶ���Ҳ�Ѿ����,��ʱֱ���л���PROBE_BWģʽ
 */
static void bbr_reset_mode(struct sock *sk)
{
	/* �������PROBE_RTTǰ����δ��, ˵������STARTUPģʽ */
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(sk);
	else /* ������PROBE_BWģʽ */
		bbr_reset_probe_bw_mode(sk);
}

/* Start a new long-term sampling interval. */
/* ����LT�ɼ�����, ���¿�ʼһ�����ڼ���
 * һ��LT�ɼ�����ʱ��: ����4��RTT���ں󶪰��ʴ���20%�Ҳ�����16��RTT����
 */
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = tp->delivered_mstamp.stamp_jiffies; /* �ɼ�������ʼʱ�� */
	bbr->lt_last_delivered = tp->delivered; /* ��ʼdelivered */
	bbr->lt_last_lost = tp->lost; /* ��ʼ�������� */
	bbr->lt_rtt_cnt = 0; /* RTT���������� */
}

/* Completely reset long-term bandwidth sampling. */
/* ����LT��������, ������Ҫ���½����ж��Ƿ����� */
static void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0; /* �������ٴ��� */
	bbr->lt_use_bw = 0; /* ����ʹ�����ٱ�־ */
	bbr->lt_is_sampling = false; /* ���ÿ�ʼ�ɼ���־ */
	bbr_reset_lt_bw_sampling_interval(sk); /* ���òɼ����� */
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
/* ����LT���������ж��Ƿ��ڲ�������㶨ʱʹ�����ٴ��� */
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 diff;

	/* �����һ�������Ѿ���LT��������Ž��д���
	 * ��Ҫ���������������ڻ�ȡ��LT�����������������ڵĲ�������"�����Ǻ㶨��"����Ϊ����������
	 */
	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - bbr->lt_bw); /* ȡ�����������ڴ����ֵ�ľ���ֵ */
		/* �����жϲ�������"�����Ǻ㶨��"�ı�׼:
		 *   �����������ڴ���Ĳ�������С��(�����)1/8
		 * ��
		 *   �����������ڴ���Ĳ�����ֵС��(�����)4KB/S
		 */ 
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
		     bbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			/* �������ٴ���Ϊ�������������ƽ��ֵ */
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
			bbr->lt_use_bw = 1; /* �����־��ʽ��ʼʹ�����ٴ��� */
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops *//* ���������²����������ֹ���� */
			bbr->lt_rtt_cnt = 0; /* RTT���ڼ�������, �����˳����ٴ��� */
			return;
		}
	}
	bbr->lt_bw = bw; /* ����LT�������� */
	bbr_reset_lt_bw_sampling_interval(sk); /* ����һ�ֲ������� */
}

/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
/* Ϊ�˼�������Ͱ�������Ʋ���, 
 * ��BBR̽�⵽��������LT�������������������Ǻ㶨�Ĳ����нϸߵĶ�����(20%),
 * ����Ϊ�м��豸�����������Ʋ���,
 * ��ô�������������ڵ�ƽ�������������ô����Ҵ���������
 */
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	s32 t;

	/* ����Ѿ��ж�Ϊ��������, ����Ҫ�ж�һ��ʱ����Ƿ��˳� */
	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		/* (�ȴ�)����PROBE_BWģʽʱ, �ۼ���ʹ��LT��RTT����,
		 * ����Ѿ���PROBE_BWģʽ��48��RTT�������˳�LT.
		 * ������Ҫ�ȴ�PROBE_BWģʽ����Ϊ:
		 * 	1.�������STARTUPģʽ��LT�����´�������Ҳ���жϴ��������Զ��˳�STARTUPģʽ
		 * 	2.�������DRAINģʽ���Ŷ��ж�������ʱҲ�����PROBE_BWģʽ
		 * 	3.�������PROBE_RTTģʽ�򵽵��ں�Ҳ���Ȼص�֮ǰ��ģʽ
		 */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			/* �˳�LT���ٴ��� */
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			/* ��������PROBE_BWģʽ���� */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	/* �ڻ�δ���ֶ���ǰ������LT�ɼ�, 
	 * �ȵ������˶�������Ϊ�������м��豸�������Ե�Ӱ�� 
	 */
	if (!bbr->lt_is_sampling) {
		if (!rs->losses) /* ��δ���ֶ���ǰ������ */
			return;
		bbr_reset_lt_bw_sampling_interval(sk); /* ���ڿ�ʼһ�ֲɼ����� */
		bbr->lt_is_sampling = true; /* ������, ���ڿ�ʼ����Ƿ������ٲ��� */
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	/* Ϊ�˱�������͹�, ��ÿ�����ݷ����(��Ӧ�ò�������)����, ���������ж��Ƿ��������� */
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(sk); /* ����LT */
		return;
	}

	/* ��¼LT�������ڵĵڼ���RTT����,
 	 * һ��LT�ɼ�����ʱ��: ����4��RTT���ں󶪰��ʴ���20%�Ҳ�����16��RTT����
	 */
	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
	/* LT����������С4��RTT���� */
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	/* LT�����������16��RTT���� */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		/* ����16��RTT���ں�����LT���� */
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	/* LT��һ������������Ҫ�ȵ������ſ��ܽ���(��������Ҫ���㶪���ʴ���20%)
	 * ��Ϊ�ж������п��������ٲ��Ե��µ�
	 */
	if (!rs->losses)
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - bbr->lt_last_lost; /* ���㱾�β��������ڶ������� */
	delivered = tp->delivered - bbr->lt_last_delivered; /* ���㱾�β������������ݽ����� */
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	/* ���������С��20%������ȵ�(ȷ�е�˵��19.5%) */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	/* �����������ʱ�� */
	t = (s32)(tp->delivered_mstamp.stamp_jiffies - bbr->lt_last_stamp);
	if (t < 1) /* ����С��1ms(jiffy), ʱ��̫�����ٵȵ� */
		return;		/* interval is less than one jiffy, so wait */
	t = jiffies_to_usecs(t); /* ת��΢�� */
	/* Interval long enough for jiffies_to_usecs() to return a bogus 0? */
	if (t < 1) { /* ����̫���˵������, �����������²ɼ� */
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	/* ������˵��һ��LT�������ڽ���
	 * ��ʼ�������: bw = delivered / interval 
	 */
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	/* ����LT���������ж��Ƿ��ڲ�������㶨ʱʹ�����ٴ��� */
	bbr_lt_bw_interval_done(sk, bw);
}

/* Estimate the bandwidth based on how fast packets are delivered */
/* ���¹������ */
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	bbr->round_start = 0; /* �յ���ACK,���ڲ��Ǳ���RTT���ڵ���ʼ�� */
	/* rate_sample�ṹ��Ч, ���� */
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	/* һ�����ڵ���, �����ǿ�ÿ�η���ʱ��¼��tp->delivered��ȷ��������ǵ� */
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered; /* ��һ�ֿ�ʼ�� */
		bbr->rtt_cnt++; /* RTT���ڵ��� */
		bbr->round_start = 1; /* ��־RTT������ʼ */
		bbr->packet_conservation = 0; /* ȡ������ģʽ, ��ģʽ��ָ����recovery�ĵ�һ��RTT���� */
	}

	/* �ж��Ƿ����long term�������� */
	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	/* ���������� bw = delivered / interval, ��λ�� pkts/us << BW_SCALE */
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	/* �����ܵ�Ӧ�ò����ݵ����ƻ�������ֵ����ʱ,��¼����
	 * ��Ϊ���ܵ�Ӧ�ò������ʱ, �������ֵ��ƫ�͵�, �����ǲ�׼ȷ��
	 */
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		/* �������󴰿ڹ���, ����10��RTT���ڹ������ֵ */
		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}

/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
/* �жϴ����Ƿ�����: �����������ڹ������������û�дﵽ25%��Ϊ������
 * 	(25%�ǵ�3��������Ե�0�����ڵ�����, ����ÿ�����ڵ���)
 * 3�����ڵ�ԭ��(bbr_full_bw_cnt)��
 * 	1.��һ�����ڽ��մ�������
 * 	2.�ڶ����������Ƿ������մ���
 * 	3.���������ڻ�ȡ�����ڵ���Ϣ
 */
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh;

	/* ���
	 * �������� �� 
	 * ��������ʼ��(ÿ������ֻ�����ж�һ��) �� 
	 * �ܵ�Ӧ�ò����� 
	 * ���˳����ж� 
	 */
	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	/* ������һ�ֹ�������125%, ���ڸ����ִ���Ƚ�
	 * 25%������������Ϊpacing rate���������Ǵ���25%��(STARTUPģʽ2.886��PROBE_BWģʽ��̽��ʱ��1.25)
	 */
	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) { /* �������������25%���� */
		bbr->full_bw = bbr_max_bw(sk); /* ���浱ǰ�Ĺ������ */
		bbr->full_bw_cnt = 0; /* ��������ʱ���� */
		return;
	}
	++bbr->full_bw_cnt; /* �������û������25%, �����ۼ� */
}

/* If pipe is probably full, drain the queue and then enter steady-state. */
/* ���STARTUP => DRAIN => PROBE_BW��ģʽ�л� */
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* ���STARTUPģʽ�д�������, �����DRAINģʽ */
	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		/* �л�ΪDRAINģʽ */
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		/* DRAINģʽpacing rate������Ϊ0.336, Ϊ�����֮ǰ�����������µ��Ŷ� */
		bbr->pacing_gain = bbr_drain_gain;	/* pace slow to drain */
		/* DRAINģʽ���������ʻ���Ϊ�ϸߵ�2.885��, 
		 * ��Ϊ֮ǰSTARTUPģʽ��inflight�Ѿ��ϴ�, ���cwnd_gain����ȼ�С��Ӱ�����ݷ���,
		 * ����inflightͻȻ���,
		 * ����Ӧ����Ҫ����pacing_gain�������ŶӶ���ƽ�ȼ�С
		 */
		bbr->cwnd_gain = bbr_high_gain;	/* maintain cwnd */
	}	/* fall through to check if in-flight is already small: */

	/* ���DRAINģʽ��inflight����������, ��˵�������е����ݰ��Ѿ�������,
	 * ��ʱ�л���PROBE_BWģʽ
	 */
	if (bbr->mode == BBR_DRAIN &&
	    tcp_packets_in_flight(tcp_sk(sk)) <=
	    bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT)) /* ���ﷵ�ص��Ǵ���ʱ�ӳ˻�ת���ɴ���
	    						    * gainΪBBR_UNITΪ1��(û������)
							    * ����BDP�Ǹ���min_rtt����õ���
							    */
	    	/* ����PROBE_BWģʽ */
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
}

/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
/* min_rtt�Ĳɼ��Լ�PROBE_RTTģʽ���� */
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	/* min_rtt��ʱ��(����10��û�и���min_rtt) */
	filter_expired = after(tcp_time_stamp,
			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);

	/* �������min_rtt: ��СRTT��С���߳�ʱ��, ������Сrtt */
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us <= bbr->min_rtt_us || filter_expired)) {
		bbr->min_rtt_us = rs->rtt_us; /* ��¼min_rtt */
		bbr->min_rtt_stamp = tcp_time_stamp; /* ��¼����ʱ��� */
	}

	/* ���min_rtt����10��δ����������PROBE_RTTģʽ,
	 * PROBE_RTTģʽ���������ʹ���(inflight<=4)������RTT̽��, 
	 * ���ͺ���Ҫά��max(200ms, 1 rtt round)��ʱ��
	 * (�մ�idle״̬(Ӧ�ò�������)�ָ�����Ҫ)
	 */
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		/* �л���PROBE_RTTģʽ */
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		/* PROBE_RTTģʽ��pacing rate��cwnd�������� */
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain = BBR_UNIT;
		/* ���浱ǰcwnd�Ա��˳�PROBE_RTTģʽ��ָ� */
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		bbr->probe_rtt_done_stamp = 0;
	}

	/* ���ﴦ��PROBE_RTTģʽ */
	if (bbr->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		/* �����������Ϊ�ܵ�Ӧ�ò���������, 
		 * ��ΪPROBE_RTTģʽ���⽵�ʹ�������ȡRTT, 
		 * ��������ΪӦ�ò����Ʒ�ֹ�����ɼ��������
		 */
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		/* ����PROBE_RTT����Ҫ�ȴ�inflight������4������ʼά������һ��RTT����200ms��ʱ�� */
		/* �����ʱ�Ǹս���PROBE_RTTģʽ, bbr_set_cwnd()�������cwnd<=4,
		 * ����ȴ�inflight<=4�������������Ľ���RTT��̽��
		 */
		if (!bbr->probe_rtt_done_stamp &&
		    tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) { /* ȷ���ʹ���, ����ά��һ��ʱ���׼���˳��� */
			/* �����˳�PROBE_RTT��ʱ��: 200ms֮�� */
			bbr->probe_rtt_done_stamp = tcp_time_stamp +
				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			bbr->probe_rtt_round_done = 0; /* ���ڸ���һ��RTT���� */
			/* ����RTT���ڴ����ڿ�ʼ����, �����ж�PROBE_RTTģʽ���پ���һ��RTT���� */
			bbr->next_rtt_delivered = tp->delivered; 
		} else if (bbr->probe_rtt_done_stamp) { /* �˳�PROBE_RTTģʽ����ʱ�� */
			/* PROBE_RTTģʽ�ڵʹ���(inflight<=4)��ά����һ��RTT���� */
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1; /* ���һ��RTT�������  */
			/* �˳�PROBE_RTTģʽ��������max(200ms, 1 round) */
			if (bbr->probe_rtt_round_done && /* ������һ��RTT */
			    after(tcp_time_stamp, bbr->probe_rtt_done_stamp)) { /* ������200ms */
				bbr->min_rtt_stamp = tcp_time_stamp; /* ����min_rtt��¼��ʱ��� */
				bbr->restore_cwnd = 1;  /* snap to prior_cwnd *//* �ָ�cwnd */
				bbr_reset_mode(sk); /* ���ص�����PROBE_RTTģʽ֮ǰ��ģʽ */
			}
		}
	}
	/* ���idle��ʼ���,��Ϊ��ʱ�Ѿ�����һ��RTT�յ���ACK */
	bbr->idle_restart = 0;
}

/* BBR���ĺ���: ��������RTT�����Լ�����ģʽ�µ��л� */
static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	bbr_update_bw(sk, rs); 		/* ���¹������ */
	bbr_update_cycle_phase(sk, rs); /* PROBE_BWģʽpacing rate������(pacing_gain)���л� */
	bbr_check_full_bw_reached(sk, rs); /* STARTUPģʽ�жϴ����Ƿ����� */
	bbr_check_drain(sk, rs); 	/* ���STARTUP => DRAIN => PROBE_BWģʽ�л� */
	bbr_update_min_rtt(sk, rs);	/* min_rtt�Ĳɼ��Լ�PROBE_RTTģʽ���� */
}

/* BBR���ĺ��� */
static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw;

	/* ��������RTT�����Լ�����ģʽ�µ��л� */
	bbr_update_model(sk, rs);
	/* ��ȡ�������, ��λΪ pkts/us << BW_SCALE */
	bw = bbr_bw(sk); 
	/* ���ݹ�������������������pacing rate */
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain); 
	/* ����pacing rate����TSOÿ���ֶεİ����� */
	bbr_set_tso_segs_goal(sk);
	/* ӵ�����ڿ��� */
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

/* ��ʼ�� */
static void bbr_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	bbr->prior_cwnd = 0;
	bbr->tso_segs_goal = 0;	 /* default segs per skb until first ACK */
	bbr->rtt_cnt = 0;
	bbr->next_rtt_delivered = 0;
	bbr->prev_ca_state = TCP_CA_Open;
	bbr->packet_conservation = 0;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = tcp_min_rtt(tp);
	bbr->min_rtt_stamp = tcp_time_stamp;

	/* ��ʼ���������Ϊ0 */
	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
	/* bw��ʼ��Ϊinit_cwnd/RTT, ��RTT��������1ms���� */
	bw = (u64)tp->snd_cwnd * BW_UNIT;
	do_div(bw, (tp->srtt_us >> 3) ? : USEC_PER_MSEC); 
	sk->sk_pacing_rate = 0;		/* force an update of sk_pacing_rate */
	/* ��ʼ��pacing rate, ����Ϊbw��2.88��, �൱�ڴ��ڵ�ָ������ */
	bbr_set_pacing_rate(sk, bw, bbr_high_gain); 

	bbr->restore_cwnd = 0;
	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp.v64 = 0;
	bbr->cycle_idx = 0;
	bbr_reset_lt_bw_sampling(sk); /* ��ʼ��LT�������� */
	bbr_reset_startup_mode(sk); /* ��ʼ��ΪSTARTUPģʽ */
}

/* ���Ʒ��ͻ������չ����, TCPĬ��Ϊ2��, BBR����Ϊ3��
 * ��ΪBBR�����ڿ��ٻָ�ʱ���������Ӵ���, 
 * Ϊ�˱��ⷢ�ͻ�������Ƶ���Ӧ�ò����ݵ�Ӱ�����ԸĴ�
 */
static u32 bbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since BBR may slow-start even during recovery. */
	return 3;
}

/* In theory BBR does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see bbr_main()). Keep it for now.
 */
/* BBR����Ҫundoӵ������, 
 * ��ΪBBR��Ҫͨ��pacing rate�����Ʒ�������, �����������ʹ���, 
 * ����BBR���˳�recovery/loss״̬ʱ�ͻ�ָ�����ʱ�Ĵ���
 */
static u32 bbr_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd; /* undoʱ���޸Ĵ��� */
}

/* Entering loss recovery, so save cwnd for when we exit or undo recovery. */
static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk); /* �����ʱcwnd, ����֮��ָ� */
	/* BBR����ʹ����������ֵssthresh, ����ֱ�ӷ������ֵ */
	return TCP_INFINITE_SSTHRESH;	 /* BBR does not use ssthresh */
}

/* ����getsockopt��TCP_CC_INFO��ȡӵ���㷨����Ϣ */
static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE; /* ����ֵ(B/s) */
		memset(&info->bbr, 0, sizeof(info->bbr));
		info->bbr.bbr_bw_lo		= (u32)bw;
		info->bbr.bbr_bw_hi		= (u32)(bw >> 32);
		info->bbr.bbr_min_rtt		= bbr->min_rtt_us;
		info->bbr.bbr_pacing_gain	= bbr->pacing_gain;
		info->bbr.bbr_cwnd_gain		= bbr->cwnd_gain;
		*attr = INET_DIAG_BBRINFO;
		return sizeof(info->bbr);
	}
	return 0;
}

/* �������LOSS״̬ */
static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* ����Loss״̬ */
	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss; /* ��¼ӵ��״̬ */
		bbr->full_bw = 0; /* ����һ�μ�¼��������, Ŀ���������жϴ����Ƿ����� */
		bbr->round_start = 1;	/* treat RTO like end of a round *//* RTO���൱������һ��RTT���ڿ�ʼ */
		bbr_lt_bw_sampling(sk, &rs); /* �ж��Ƿ����LT�������� */
	}
}

static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "bbr",
	.owner		= THIS_MODULE,
	.init		= bbr_init,
	/* �ýӿڽӹ�������ӵ�����ڵĴ������(��������ӵ��״̬)�Լ�pacing rate������
	 * ��BBR����Ҫ����, ȡ���˴�ͳ��cong_avoid�ӿ�
	 */
	.cong_control	= bbr_main,
	/* �ýӿڿ��Ʒ��ͻ������չ����, TCPĬ��Ϊ2��, BBR����Ϊ3�� */
	.sndbuf_expand	= bbr_sndbuf_expand,
	.undo_cwnd	= bbr_undo_cwnd, /* BBR undoʱ���޸�ӵ������ */
	.cwnd_event	= bbr_cwnd_event,
	.ssthresh	= bbr_ssthresh, /* ������cwndֵ, BBR��ʹ����������ֵ */
	/* �ýӿ����ڿ���TSO�εĴ�С, ����0��ʾĬ���Զ����� */
	.tso_segs_goal	= bbr_tso_segs_goal,
	.get_info	= bbr_get_info, /* ����getsockopt��ȡӵ���㷨����Ϣ */
	.set_state	= bbr_set_state, /* �������LOSS״̬ */
};

static int __init bbr_register(void)
{
	BUILD_BUG_ON(sizeof(struct bbr) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_bbr_cong_ops);
}

static void __exit bbr_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_bbr_cong_ops);
}

module_init(bbr_register);
module_exit(bbr_unregister);

MODULE_AUTHOR("Van Jacobson <vanj@google.com>");
MODULE_AUTHOR("Neal Cardwell <ncardwell@google.com>");
MODULE_AUTHOR("Yuchung Cheng <ycheng@google.com>");
MODULE_AUTHOR("Soheil Hassas Yeganeh <soheil@google.com>");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP BBR (Bottleneck Bandwidth and RTT)");
