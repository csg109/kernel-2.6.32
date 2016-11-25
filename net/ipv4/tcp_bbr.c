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
#define BBR_UNIT (1 << BBR_SCALE) /* 带宽计算时扩大的单位 */

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode { /* BBR的模式 */
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
			/* 连接开始时快速探测带宽, 相当于慢启动,
			 * 直到认为带宽用满时主动进入DRAIN模式
			 */
	BBR_DRAIN,	/* drain any queue created during startup */
			/* DRAIN模式目的是清除之前STARTUP模式积累的排队队列 
			 * 直到排队队列的数据包完全清除再退出DRAIN模式进入PROBE_BW模式
			 */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
			/* PROBE_BW模式的特点是将一段时间分成8个时间片，然后顺序循环地进行:
			 * a.增加发送速率（pacing_gain = 1.25）来探测带宽（1个时间片）；
			 * b.降低发送速率（pacing_gain = 0.75）来清除排队队列（1个时间片）；
			 * c.维持发送速率不变（pacing_gain =1）来充分利用带宽而不增加排队队列（6个时间片）
			 */
	BBR_PROBE_RTT,	/* cut cwnd to min to probe min_rtt */
			/* PROBE_RTT模式用于在min_rtt超时未更新（10秒未更新）时主动降低带宽来探测RTT。
			 * 进入PROBE_RTT模式后，会将cwnd设置为不超过4，仅在链路上容许少量数据包来获取准确的min_rtt，
			 * PROBE_RTT模式会等到inflight<=4后维持max(200 ms, 1 round)的时间然后退出PROBE_RTT模式恢复之前的模式，
			 * 在低带宽维持至少一个RTT周期保证能采集到min_rtt。
			 * 任何模式下都可能进入PROBE_RTT模式，
			 * 并且退出PROBE_RTT模式后会返回之前的模式（cwnd也会恢复之前大小）
			 */
};

/* BBR congestion control block */
struct bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
					/* 经过10秒窗口过滤的最小RTT, 单位微秒 */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
					/* 记录min_rtt_us时的时间戳, 用于判断min_rtt_us过期 */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
				        /* 退出PROBE_RTT模式的时间点, 即inflight<=4后加上200ms的时间 */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
				/* 估算带宽, 单位为 pkts/us << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
				    /* 记录第几个RTT周期, 用于估算带宽采样的窗口过滤 */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
				    /* 记录每轮RTT周期起始时tp->delivered, 用于判断每轮RTT周期结束 */
	struct skb_mstamp cycle_mstamp;  /* time of this cycle phase start */
					 /* PROBE_BW模式中记录pacing rata增长速率数组bbr_pacing_gain切换时的起点时间 */
	u32     mode:3,		     /* current bbr_mode in state machine */
				     /* 当前BBR模式, 由enum bbr_mode定义 */
		prev_ca_state:3,     /* CA state on previous ACK */
				     /* 上一个ACK的拥塞状态 */
		packet_conservation:1,  /* use packet conservation? */
				     /* 保守模式: 刚进入快速恢复的第一个RTT周期内使用保守模式, 收到P个包的确认发送P个包 */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
				     /* 设置需要恢复进入丢包状态(recovery/loss)的拥塞窗口 */
		round_start:1,	     /* start of packet-timed tx->ack round? */
				     /* 表示当前是本轮RTT周期的起始 */
		tso_segs_goal:7,     /* segments we want in each skb we send */
				     /* TSO每个分段的包个数, 是根据pacing rate计算每ms包个数得到 */
		idle_restart:1,	     /* restarting after idle? */
				     /* 标记刚从idle(应用层无数据)恢复开始发送数据 */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
					 /* PROBE_RTT模式中用于标记经历了一轮RTT周期 */
		unused:5,	     /* 未使用 */
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
				     /* 是否进行LT采集(出现丢包后才开始) */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
				     /* 记录LT采集周期(或已经确认使用LT)的第几个RTT周期 */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
				     /* 标志是否使用LT限速带宽, 即已经确认为限速网络 */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
				     /* LT限速带宽, 根据LT采样周期内的交付量和周期计算 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
			     	     /* LT采集周期起始的delivered, 用于周期结束后计算交付量 */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
				     /* LT采集周期起始的时间, 用于周期结束后计算周期时间长度 */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
				     /* LT采集周期起始的丢包数, 用于计算周期内的丢包率 */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
				/* 当前pacing rate的增长速率
				 * STARTUP模式为bbr_high_gain(2.885)
				 * DRAIN模式为bbr_drain_gain(0.336)
				 * PROBE_BW模式是动态调整的,根据时间片在bbr_pacing_gain数组轮询
				 * PROBE_RTT模式为BBR_UNIT(1)
				 * LT(long-term限速网络)为BBR_UNIT(1)
				 */
		cwnd_gain:10,	/* current gain for setting cwnd */
				/* 当前cwnd的增长速率
				 * STARTUP模式为bbr_high_gain(2.885)
				 * DRAIN模式为bbr_high_gain(2.885)
				 * PROBE_BW模式为bbr_cwnd_gain(2)
				 * PROBE_RTT模式为BBR_UNIT(1)
				 * LT(long-term限速网络)维持对应模式下的值
				 */
		full_bw_cnt:3,	/* number of rounds without large bw gains */
				/* 表示已经连续几个周期估算带宽没有增长了, 用来判断带宽已满 */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
				/* PROBE_BW模式中当前pacing_gain对应bbr_pacing_gain数组的下标 */
		unused_b:6;	/* 未使用 */
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
				/* 保存(第一次)进入RECOVERY/LOSS时的cwnd, 以便undo */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */
				/* 上一个周期的估算带宽, 用于判断估算带宽有没有增长 */
};

#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2; /* 带宽过滤窗口长度为10个周期 */
/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10; /* min_rtt窗口过滤常去, 10秒 */
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200; /* PROBE_RTT模式维持在低带宽的最小时间 */
/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000; /* 即150KB/S */

/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
/* bbr_high_gain为慢启动的增长速率, 设置为 2/ln2 = 2.885倍, 
 * pacing rate的2/ln(2)相当于传统慢启动的每个RTT窗口翻倍
 */
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1; /* 含义为2.885倍 */
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
/* DRAIN模式pacing rate增长率, 为1/high_gain = 0.336 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885; /* 为0.336倍 */
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
/* PROBE_BW模式cwnddeep增长率为2倍 */
static const int bbr_cwnd_gain  = BBR_UNIT * 2; /* 为2倍 */

/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
/* PROBE_BW模式将一段时间分成8个时间片(每个时间片长度为min_rtt)，然后顺序循环地进行：
 * 1.增加发送速率（pacing_gain = 1.25）来探测带宽（1个时间片）；
 * 2.降低发送速率（pacing_gain = 0.75）来清除排队队列（1个时间片）；
 * 3.维持发送速率不变（pacing_gain =1）来充分利用带宽而不增加排队队列（6个时间片）。
 */
static const int bbr_pacing_gain[] = {
	/* 1个时间片的1.25倍增长, 探测带宽 */
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	/* 1个时间片的0.75倍减小, 清除排队队列 */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	/* 6个时间片维持带宽不变, 充分利用带宽但不增长排队队列 */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
/* 用于进入PROBE_BW模式时随机选择pacing_gain下标 */
static const u32 bbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4; /* 拥塞窗口/inflight最小值为4 */

/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
/* 如果STARTUP模式连续3个周期增长率没有达到25%, 则认为带宽已满 */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4; /* 125%, 即增长率25% */
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 bbr_full_bw_cnt = 3; /* 如果3个周期内估算带宽没有增加则说明带宽满了 */

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
/* 控制LT采样周期时间长度：
 * 	最小bbr_lt_intvl_min_rtts 最大4*bbr_lt_intvl_min_rtts, 单位为RTT周期
 * 	即[4 round, 16 round]
 */
static const u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
/* LT周期采样阈值丢包率, 即当该周期丢包率超过20%时才认为周期结束
 * 计算规则是 阈值丢包率 = bbr_lt_loss_thresh / BBR_UNIT = 50 / 256 = 19.5%(大概20%)
 */
static const u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
/* LT中判断两个采样周期带宽的波动比例小于(或等于)1/8 则认为是限速网络(中间设备存在流量策略) */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
/* LT中判断两个采样周期带宽的波动差值小于(或等于)4KB/s 则认为是限速网络(中间设备存在流量策略) */
static const u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
/* LT限速带宽使用的最大RTT周期数, 用于在使用LT一段时间后退出返回 */
static const u32 bbr_lt_bw_max_rtts = 48;

/* Do we estimate that STARTUP filled the pipe? */
/* 返回带宽是否已满, 即如果有连续3个周期估算带宽没有增长25%, 则认为带宽满 */
static bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_cnt >= bbr_full_bw_cnt;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
/* 返回经过最大窗口过滤后的估算带宽, 单位为 pkts/us << BW_SCALE */
static u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
/* 返回估算带宽, 单位为 pkts/us << BW_SCALE */
static u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* 如果判断为LT限速网络, 则返回限速带宽,
	 * 否则返回正常的估算带宽
	 */
	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
/* 将单位为(pkts/us << 24)的带宽(发送速率)@rate乘以(@gain >> 8)倍数并转化成bytes/sec单位 */
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
/* 通过带宽@bw和乘法因子@gain设置pacing rate 
 * 另外上面注释提到: 
 * 	设置的pacing rate稍稍小于带宽(bbr_update_bw()中计算带宽pkts/us没有向上取整)
 * 	是因为考虑到pacing rate并没有包含链路头的大小(理论上大概需要少1%)
 */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u64 rate = bw;

	/* 获取带宽bw的gain倍,单位为bytes/sec */
	rate = bbr_rate_bytes_per_sec(sk, rate, gain); 
	/* 不超过最大带宽,应用层设置,默认为最大~0值 */
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	/* 设置pacing rate, 如果处于STARTUP模式则只能增加 */
	if (bbr->mode != BBR_STARTUP || rate > sk->sk_pacing_rate)
		sk->sk_pacing_rate = rate;
}

/* Return count of segments we want in the skbs we send, or 0 for default. */
/* 返回每个TSO分段的数据包个数, 0表示默认处理 */
static u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	return bbr->tso_segs_goal;
}

/* 根据pacing rate设置TSO每个分段的包个数 */
static void bbr_set_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 min_segs;

	/* 设置最小TSO每个分段包个数: 如果pacing rate发送速率小于150KB/S则为1, 否则为2 */
	min_segs = sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
	/* 设置TSO每个分段的包个数: tcp_tso_autosize函数将pacing rate转化为每ms的包个数返回
	 * 这里还限制最大值127
	 */
	bbr->tso_segs_goal = min(tcp_tso_autosize(sk, tp->mss_cache, min_segs),
				 0x7FU);
}

/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
/* 保存cwnd, 便于之后恢复 */
static void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	/* 第一次进入RECOVERY/LOSS, 直接保存窗口值 */
	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	/* 非首次进入RECOVERY/LOSS或处于PROBE_RTT模式, 取两者大的 */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tp->snd_cwnd);
}

/* 主要处理从idle恢复后的事件 */
static void bbr_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	/* 之前应用层无数据, 现在重新开始发送数据 */
	if (event == CA_EVENT_TX_START && tp->app_limited) {
		bbr->idle_restart = 1; /* 标志从idle恢复 */
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		/* 此时如果是在PROBE_BW模式, pacing rate暂时不增长,
		 * 因为此时刚从idle恢复并不需要那么快, 目的是使pacing发送平稳
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
/* 返回目标拥塞窗口大小
 * 计算方式为: 
 * 	cwnd = bw * min_rtt * gain = BDP * gain, 即目标拥塞窗口为BDP的gain倍数
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
	/* 当此时没有min_rtt值时(所有数据包都被重传过),
	 * 这种情况下窗口可能会被RTO设置为1, 所以这里我们可以慢启动到比较安全的窗口: 初始窗口
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * bbr->min_rtt_us; /*  计算BDP, 单位是 包个数<<BW_SCALE */

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	/* 计算BDP的gain倍数, 并向上取整 */
	cwnd = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	/* 再增加3个TSO分段, 考虑到终端的缓存? */
	cwnd += 3 * bbr->tso_segs_goal;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	/* 考虑到delay-ack, 奇数加1 */
	cwnd = (cwnd + 1) & ~1U;

	return cwnd; /* 返回目标拥塞窗口 */
}

/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
/* 控制丢包状态(recovery/loss状态)下的拥塞窗口控制模式 
 * 返回true表示处于保守模式
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
	/* 如果发生了新的丢包, 这里先把窗口减掉丢包的个数
	 * 非保守模式后续会在bbr_set_cwnd()中再慢启动到目标窗口
	 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	/* 刚进入RECOVERY状态, 第一个RTT周期使用保守模式: 每收到P个包的确认发送P个包, 保持数据包守恒 */
	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		bbr->packet_conservation = 1; /* 标志保守模式 */
		bbr->next_rtt_delivered = tp->delivered;  /* start round now *//* 记录保守模式起点,用于判断退出时机 */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = tcp_packets_in_flight(tp) + acked; /* 保守模式保持数据包守恒 */
	/* 刚从丢包恢复(LOSS或RECOVERY状态)退出 */
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		bbr->restore_cwnd = 1; /* 设置需要撤销窗口 */
		bbr->packet_conservation = 0; /* 取消保守模式 */
	}
	bbr->prev_ca_state = state; /* 记录拥塞状态 */

	/* 从丢包状态恢复时撤销之前拥塞窗口的减小, 恢复为进入丢包状态的拥塞窗口 */
	if (bbr->restore_cwnd) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, bbr->prior_cwnd);
		bbr->restore_cwnd = 0;
	}

	/* 保守模式, 保持数据包守恒: 确认P个包发送P个包 */
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
/* 拥塞窗口控制:
 * 1.如果增加新的丢包, 则窗口首先减去丢包个数: cwnd1 = cwnd - loss
 * 2.如果是进入recovery的第一个RTT周期内则保守模式: 
 * 	保持包守恒, 确认P个包发送P个包, cwnd = inflight + acked
 * 3.否则拥塞窗口收敛到目标窗口, 具体为
 *   计算目标窗口(带宽时延乘积的gain倍): 
 *       target_cwnd = BDP * gain = bw * rtt_min *gain
 *   a.如果此时带宽已满(连续3个周期估算带宽没有增加): cwnd = min(cwnd1 + acked, target_cwnd)
 *   b.如果小于目标窗口则慢启动增加: cwnd = cwnd1 + acked
 *   c.否则 cwnd = cwnd1
 */
static void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 u32 acked, u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	/* 无确认数据包(ACK/SACK)不调整 */
	if (!acked)
		return;

	/* 先处理丢包状态下的拥塞窗口, 
	 * 返回true表示处于刚进入快速恢复的保守模式中, 这时不增加拥塞窗口
	 */
	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	/* 获取目标拥塞窗口, 如果小于目标拥塞窗口则慢启动增加窗口 */
	target_cwnd = bbr_target_cwnd(sk, bw, gain); /* 获取目标拥塞窗口 */
	/* 如果带宽已用满(说明已经退出STARTUP模式), 
	 * 慢启动增加但是最大需要限制为目标窗口大小(当带宽降低时窗口也会减小)
	 */
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	/* 否则如果当前拥塞窗口小于目标窗口(或还处于第一个周期内), 则慢启动增加 */
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target); /* 拥塞窗口最小值为4 */

done:
	/* 设置拥塞窗口 */
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
	/* 如果是PROBE_RTT模式, 则控制cwnd不能超过4个 */
	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
		tp->snd_cwnd = min(tp->snd_cwnd, bbr_cwnd_min_target);
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
/* 判断PROBE_BW状态下是否需要切换pacing rate增长率(pacing_gain) */
static bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	/* 判断时间片是否到期, 一个时间片为一个min_rtt */
	bool is_full_length =
		skb_mstamp_us_delta(&tp->delivered_mstamp, &bbr->cycle_mstamp) >
		bbr->min_rtt_us;
	u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	/* pacing rate增长率为1.0时(不增长保持充分利用带宽但不增加排队队列),
	 * 时间片完全用完后才切换增长率
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
	/* 当pacing rate的增长率大于1(即1.25), 
	 * 需要等到时间片用完 并且 发生了丢包或者inflight过大(大于1.25倍BDP)才切换,
	 * 确保探测带宽的效果
	 */
	if (bbr->pacing_gain > BBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= bbr_target_cwnd(sk, bw, bbr->pacing_gain));

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	/* 当pacing rate增长率小于1(即0.75),
	 * 等到时间片满或者inflight小于BDP时切换
	 */
	return is_full_length ||
		inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
}

/* 循环设置pacing rate增长率: pacing_gain参数数组bbr_pacing_gain */
static void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1); /* 当前下标循环加1 */
	bbr->cycle_mstamp = tp->delivered_mstamp; /* 记录切换的起始时间 */
	bbr->pacing_gain = bbr_pacing_gain[bbr->cycle_idx]; /* 切换pacing_gain */
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
/* 控制PROBE_BW模式pacing rate增长率(pacing_gain)的切换 */
static void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* PROBE_BW模式且不存在流量控制策略(非限速网络)时, 控制pacing rate增长率的切换 */
	if ((bbr->mode == BBR_PROBE_BW) && !bbr->lt_use_bw &&
	    bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk); /* 循环切换pacing rate增长率 */
}

/* 重置为STARTUP模式 */
static void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = bbr_high_gain;
	bbr->cwnd_gain	 = bbr_high_gain;
}

/* 进入PROBE_BW模式 */
static void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW; /* 切换为PROBE_BW模式 */
	bbr->pacing_gain = BBR_UNIT; /* 这里设置没意义, 马上被后面bbr_advance_cycle_phase()覆盖 */
	bbr->cwnd_gain = bbr_cwnd_gain; /* PROBE_BW模式cwnd增长率为固定的2倍 */
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand); /* 随机选择bbr_pacing_gain数组下标 */
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle *//* 设置pacing rate增长率 */
}

/* 返回到进入PROBE_RTT模式之前的模式
 * 这里没考虑DRAIN模式是因为
 * 	PROBE_RTT模式中主动降低带宽后排队队列也已经清除,此时直接切换到PROBE_BW模式
 */
static void bbr_reset_mode(struct sock *sk)
{
	/* 如果进入PROBE_RTT前带宽未满, 说明处于STARTUP模式 */
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(sk);
	else /* 否则处于PROBE_BW模式 */
		bbr_reset_probe_bw_mode(sk);
}

/* Start a new long-term sampling interval. */
/* 重置LT采集周期, 重新开始一轮周期计算
 * 一个LT采集周期时间: 至少4个RTT周期后丢包率大于20%且不超过16个RTT周期
 */
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = tp->delivered_mstamp.stamp_jiffies; /* 采集周期起始时间 */
	bbr->lt_last_delivered = tp->delivered; /* 起始delivered */
	bbr->lt_last_lost = tp->lost; /* 起始丢包个数 */
	bbr->lt_rtt_cnt = 0; /* RTT周期数清零 */
}

/* Completely reset long-term bandwidth sampling. */
/* 重置LT限速网络, 后续需要重新进行判断是否限速 */
static void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0; /* 重置限速带宽 */
	bbr->lt_use_bw = 0; /* 重置使用限速标志 */
	bbr->lt_is_sampling = false; /* 重置开始采集标志 */
	bbr_reset_lt_bw_sampling_interval(sk); /* 重置采集周期 */
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
/* 设置LT采样带宽并判断是否在采样带宽恒定时使用限速带宽 */
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 diff;

	/* 如果上一个周期已经有LT采样带宽才进行处理
	 * 需要连续两个采样周期获取到LT采样带宽并且两个周期的采样带宽"几乎是恒定的"才认为是限速网络
	 */
	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - bbr->lt_bw); /* 取两个采样周期带宽差值的绝对值 */
		/* 这里判断采样带宽"几乎是恒定的"的标准:
		 *   两个采样周期带宽的波动比例小于(或等于)1/8
		 * 或
		 *   两个采样周期带宽的波动差值小于(或等于)4KB/S
		 */ 
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
		     bbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			/* 设置限速带宽为两个采样带宽的平均值 */
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
			bbr->lt_use_bw = 1; /* 这里标志正式开始使用限速带宽 */
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops *//* 限速网络下不增长带宽防止丢包 */
			bbr->lt_rtt_cnt = 0; /* RTT周期计数清零, 用于退出限速带宽 */
			return;
		}
	}
	bbr->lt_bw = bw; /* 设置LT采样带宽 */
	bbr_reset_lt_bw_sampling_interval(sk); /* 重新一轮采样周期 */
}

/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
/* 为了兼容令牌桶流量控制策略, 
 * 当BBR探测到连续两个LT采样周期内吞吐量都是恒定的并且有较高的丢包率(20%),
 * 则认为中间设备存在流量控制策略,
 * 那么根据这两个周期的平均交付率来设置带宽且带宽不增长。
 */
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	s32 t;

	/* 如果已经判断为限速网络, 则需要判断一段时间后是否退出 */
	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		/* (等待)处于PROBE_BW模式时, 累加已使用LT的RTT周期,
		 * 如果已经在PROBE_BW模式下48个RTT周期则退出LT.
		 * 这里需要等待PROBE_BW模式是因为:
		 * 	1.如果处于STARTUP模式则LT限速下带宽不增长也会判断带宽用满自动退出STARTUP模式
		 * 	2.如果处于DRAIN模式则当排队列队清除完成时也会进入PROBE_BW模式
		 * 	3.如果处于PROBE_RTT模式则到到期后也会先回到之前的模式
		 */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			/* 退出LT限速带宽 */
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			/* 重新设置PROBE_BW模式参数 */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	/* 在还未出现丢包前不进行LT采集, 
	 * 等到出现了丢包才认为可能有中间设备流量策略的影响 
	 */
	if (!bbr->lt_is_sampling) {
		if (!rs->losses) /* 在未发现丢包前不处理 */
			return;
		bbr_reset_lt_bw_sampling_interval(sk); /* 现在开始一轮采集周期 */
		bbr->lt_is_sampling = true; /* 丢包了, 现在开始检测是否有限速策略 */
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	/* 为了避免带宽被低估, 在每次数据发完后(即应用层无数据)重置, 后续重新判断是否限速网络 */
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(sk); /* 重置LT */
		return;
	}

	/* 记录LT采样周期的第几个RTT周期,
 	 * 一个LT采集周期时间: 至少4个RTT周期后丢包率大于20%且不超过16个RTT周期
	 */
	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
	/* LT采样周期最小4个RTT周期 */
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	/* LT采样周期最大16个RTT周期 */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		/* 大于16个RTT周期后重新LT采样 */
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	/* LT的一个采样周期需要等到丢包才可能结束(后续还需要满足丢包率大于20%)
	 * 因为有丢包才有可能是限速策略导致的
	 */
	if (!rs->losses)
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - bbr->lt_last_lost; /* 计算本次采样周期内丢包个数 */
	delivered = tp->delivered - bbr->lt_last_delivered; /* 计算本次采样周期内数据交付量 */
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	/* 如果丢包率小于20%则继续等等(确切的说是19.5%) */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	/* 计算采样周期时间 */
	t = (s32)(tp->delivered_mstamp.stamp_jiffies - bbr->lt_last_stamp);
	if (t < 1) /* 周期小于1ms(jiffy), 时间太短了再等等 */
		return;		/* interval is less than one jiffy, so wait */
	t = jiffies_to_usecs(t); /* 转成微秒 */
	/* Interval long enough for jiffies_to_usecs() to return a bogus 0? */
	if (t < 1) { /* 周期太长了导致溢出, 重置周期重新采集 */
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	/* 到这里说明一个LT采样周期结束
	 * 开始计算带宽: bw = delivered / interval 
	 */
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	/* 设置LT采样带宽并判断是否在采样带宽恒定时使用限速带宽 */
	bbr_lt_bw_interval_done(sk, bw);
}

/* Estimate the bandwidth based on how fast packets are delivered */
/* 更新估算带宽 */
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	u64 bw;

	bbr->round_start = 0; /* 收到了ACK,现在不是本轮RTT周期的起始了 */
	/* rate_sample结构无效, 返回 */
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	/* 一轮周期到了, 周期是靠每次发送时记录的tp->delivered被确认了来标记的 */
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered; /* 下一轮开始了 */
		bbr->rtt_cnt++; /* RTT周期递增 */
		bbr->round_start = 1; /* 标志RTT周期起始 */
		bbr->packet_conservation = 0; /* 取消保守模式, 该模式是指进入recovery的第一个RTT周期 */
	}

	/* 判断是否存在long term限速网络 */
	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	/* 计算估算带宽 bw = delivered / interval, 单位是 pkts/us << BW_SCALE */
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
	/* 当不受到应用层数据的限制或带宽采样值增大时,记录采样
	 * 因为当受到应用层的限制时, 带宽采样值是偏低的, 数据是不准确的
	 */
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		/* 带宽的最大窗口过滤, 按照10个RTT周期过滤最大值 */
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
/* 判断带宽是否已满: 连续三个周期估算带宽增长率没有达到25%认为带宽满
 * 	(25%是第3个周期相对第0个周期的增长, 而非每个周期递增)
 * 3个周期的原因(bbr_full_bw_cnt)：
 * 	1.第一个周期接收窗口增长
 * 	2.第二个周期我们发满接收窗口
 * 	3.第三个周期获取满窗口的信息
 */
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw_thresh;

	/* 如果
	 * 带宽已满 或 
	 * 非周期起始点(每个周期只进入判断一次) 或 
	 * 受到应用层限制 
	 * 则退出不判断 
	 */
	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	/* 计算上一轮估算带宽的125%, 用于跟本轮带宽比较
	 * 25%的增长率是因为pacing rate的增长率是大于25%的(STARTUP模式2.886和PROBE_BW模式中探测时的1.25)
	 */
	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) { /* 估算带宽增长了25%以上 */
		bbr->full_bw = bbr_max_bw(sk); /* 保存当前的估算带宽 */
		bbr->full_bw_cnt = 0; /* 带宽增长时清零 */
		return;
	}
	++bbr->full_bw_cnt; /* 估算带宽没有增长25%, 计数累加 */
}

/* If pipe is probably full, drain the queue and then enter steady-state. */
/* 检查STARTUP => DRAIN => PROBE_BW的模式切换 */
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* 如果STARTUP模式中带宽已满, 则进入DRAIN模式 */
	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		/* 切换为DRAIN模式 */
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		/* DRAIN模式pacing rate增长率为0.336, 为了清除之前快速增长导致的排队 */
		bbr->pacing_gain = bbr_drain_gain;	/* pace slow to drain */
		/* DRAIN模式窗口增长率还是为较高的2.885倍, 
		 * 因为之前STARTUP模式中inflight已经较大, 如果cwnd_gain大幅度减小会影响数据发送,
		 * 导致inflight突然骤减,
		 * 所以应该主要降低pacing_gain来控制排队队列平稳减小
		 */
		bbr->cwnd_gain = bbr_high_gain;	/* maintain cwnd */
	}	/* fall through to check if in-flight is already small: */

	/* 如果DRAIN模式中inflight不超过带宽, 则说明队列中的数据包已经清除完成,
	 * 这时切换成PROBE_BW模式
	 */
	if (bbr->mode == BBR_DRAIN &&
	    tcp_packets_in_flight(tcp_sk(sk)) <=
	    bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT)) /* 这里返回的是带宽时延乘积转换成窗口
	    						    * gain为BBR_UNIT为1倍(没有扩大)
							    * 并且BDP是根据min_rtt计算得到的
							    */
	    	/* 进入PROBE_BW模式 */
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
/* min_rtt的采集以及PROBE_RTT模式处理 */
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	/* min_rtt超时了(超过10秒没有更新min_rtt) */
	filter_expired = after(tcp_time_stamp,
			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);

	/* 这里过滤min_rtt: 最小RTT变小或者超时了, 覆盖最小rtt */
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us <= bbr->min_rtt_us || filter_expired)) {
		bbr->min_rtt_us = rs->rtt_us; /* 记录min_rtt */
		bbr->min_rtt_stamp = tcp_time_stamp; /* 记录现在时间戳 */
	}

	/* 如果min_rtt超过10秒未更新则会进入PROBE_RTT模式,
	 * PROBE_RTT模式会主动降低带宽(inflight<=4)来进行RTT探测, 
	 * 降低后需要维持max(200ms, 1 rtt round)的时间
	 * (刚从idle状态(应用层无数据)恢复则不需要)
	 */
	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		/* 切换到PROBE_RTT模式 */
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		/* PROBE_RTT模式下pacing rate和cwnd都不增长 */
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain = BBR_UNIT;
		/* 保存当前cwnd以便退出PROBE_RTT模式后恢复 */
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		bbr->probe_rtt_done_stamp = 0;
	}

	/* 这里处理PROBE_RTT模式 */
	if (bbr->mode == BBR_PROBE_RTT) {
		/* Ignore low rate samples during this mode. */
		/* 这里故意设置为受到应用层数据限制, 
		 * 因为PROBE_RTT模式故意降低带宽来获取RTT, 
		 * 所以设置为应用层限制防止带宽被采集进入计算
		 */
		tp->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		/* 进入PROBE_RTT后需要等待inflight不超过4个并开始维持至少一个RTT并且200ms的时间 */
		/* 如果此时是刚进入PROBE_RTT模式, bbr_set_cwnd()里会设置cwnd<=4,
		 * 这里等待inflight<=4后才算进行真正的进行RTT的探测
		 */
		if (!bbr->probe_rtt_done_stamp &&
		    tcp_packets_in_flight(tp) <= bbr_cwnd_min_target) { /* 确保低带宽, 可以维持一段时间后准备退出了 */
			/* 设置退出PROBE_RTT的时间: 200ms之后 */
			bbr->probe_rtt_done_stamp = tcp_time_stamp +
				msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			bbr->probe_rtt_round_done = 0; /* 用于跟踪一个RTT周期 */
			/* 本轮RTT周期从现在开始算起, 用于判断PROBE_RTT模式至少经历一个RTT周期 */
			bbr->next_rtt_delivered = tp->delivered; 
		} else if (bbr->probe_rtt_done_stamp) { /* 退出PROBE_RTT模式倒计时了 */
			/* PROBE_RTT模式在低带宽(inflight<=4)下维持了一个RTT周期 */
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1; /* 标记一个RTT周期完成  */
			/* 退出PROBE_RTT模式的条件：max(200ms, 1 round) */
			if (bbr->probe_rtt_round_done && /* 经过了一轮RTT */
			    after(tcp_time_stamp, bbr->probe_rtt_done_stamp)) { /* 经过了200ms */
				bbr->min_rtt_stamp = tcp_time_stamp; /* 更新min_rtt记录的时间戳 */
				bbr->restore_cwnd = 1;  /* snap to prior_cwnd *//* 恢复cwnd */
				bbr_reset_mode(sk); /* 返回到进入PROBE_RTT模式之前的模式 */
			}
		}
	}
	/* 清除idle起始标记,因为此时已经经过一轮RTT收到了ACK */
	bbr->idle_restart = 0;
}

/* BBR核心函数: 负责带宽和RTT计算以及各个模式下的切换 */
static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	bbr_update_bw(sk, rs); 		/* 更新估算带宽 */
	bbr_update_cycle_phase(sk, rs); /* PROBE_BW模式pacing rate增长率(pacing_gain)的切换 */
	bbr_check_full_bw_reached(sk, rs); /* STARTUP模式判断带宽是否已满 */
	bbr_check_drain(sk, rs); 	/* 检测STARTUP => DRAIN => PROBE_BW模式切换 */
	bbr_update_min_rtt(sk, rs);	/* min_rtt的采集以及PROBE_RTT模式处理 */
}

/* BBR核心函数 */
static void bbr_main(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	u32 bw;

	/* 负责带宽和RTT计算以及各个模式下的切换 */
	bbr_update_model(sk, rs);
	/* 获取估算带宽, 单位为 pkts/us << BW_SCALE */
	bw = bbr_bw(sk); 
	/* 根据估算带宽和增长速率设置pacing rate */
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain); 
	/* 根据pacing rate设置TSO每个分段的包个数 */
	bbr_set_tso_segs_goal(sk);
	/* 拥塞窗口控制 */
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
}

/* 初始化 */
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

	/* 初始化估算带宽为0 */
	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
	/* bw初始化为init_cwnd/RTT, 若RTT不存在则当1ms处理 */
	bw = (u64)tp->snd_cwnd * BW_UNIT;
	do_div(bw, (tp->srtt_us >> 3) ? : USEC_PER_MSEC); 
	sk->sk_pacing_rate = 0;		/* force an update of sk_pacing_rate */
	/* 初始化pacing rate, 设置为bw的2.88倍, 相当于窗口的指数增长 */
	bbr_set_pacing_rate(sk, bw, bbr_high_gain); 

	bbr->restore_cwnd = 0;
	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp.v64 = 0;
	bbr->cycle_idx = 0;
	bbr_reset_lt_bw_sampling(sk); /* 初始化LT限速网络 */
	bbr_reset_startup_mode(sk); /* 初始化为STARTUP模式 */
}

/* 控制发送缓存的扩展倍数, TCP默认为2倍, BBR设置为3倍
 * 因为BBR可能在快速恢复时慢启动增加窗口, 
 * 为了避免发送缓存的限制导致应用层数据的影响所以改大
 */
static u32 bbr_sndbuf_expand(struct sock *sk)
{
	/* Provision 3 * cwnd since BBR may slow-start even during recovery. */
	return 3;
}

/* In theory BBR does not need to undo the cwnd since it does not
 * always reduce cwnd on losses (see bbr_main()). Keep it for now.
 */
/* BBR不需要undo拥塞窗口, 
 * 因为BBR主要通过pacing rate来控制发送速率, 并不经常降低窗口, 
 * 并且BBR在退出recovery/loss状态时就会恢复进入时的窗口
 */
static u32 bbr_undo_cwnd(struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd; /* undo时不修改窗口 */
}

/* Entering loss recovery, so save cwnd for when we exit or undo recovery. */
static u32 bbr_ssthresh(struct sock *sk)
{
	bbr_save_cwnd(sk); /* 保存此时cwnd, 便于之后恢复 */
	/* BBR并不使用慢启动阈值ssthresh, 所以直接返回最大值 */
	return TCP_INFINITE_SSTHRESH;	 /* BBR does not use ssthresh */
}

/* 用于getsockopt的TCP_CC_INFO获取拥塞算法的信息 */
static size_t bbr_get_info(struct sock *sk, u32 ext, int *attr,
			   union tcp_cc_info *info)
{
	if (ext & (1 << (INET_DIAG_BBRINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcp_sock *tp = tcp_sk(sk);
		struct bbr *bbr = inet_csk_ca(sk);
		u64 bw = bbr_bw(sk);

		bw = bw * tp->mss_cache * USEC_PER_SEC >> BW_SCALE; /* 带宽值(B/s) */
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

/* 处理进入LOSS状态 */
static void bbr_set_state(struct sock *sk, u8 new_state)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* 进入Loss状态 */
	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss; /* 记录拥塞状态 */
		bbr->full_bw = 0; /* 将上一次记录带宽清零, 目的是重新判断带宽是否已满 */
		bbr->round_start = 1;	/* treat RTO like end of a round *//* RTO后相当于重新一个RTT周期开始 */
		bbr_lt_bw_sampling(sk, &rs); /* 判断是否存在LT限速网络 */
	}
}

static struct tcp_congestion_ops tcp_bbr_cong_ops __read_mostly = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "bbr",
	.owner		= THIS_MODULE,
	.init		= bbr_init,
	/* 该接口接管了所有拥塞窗口的处理过程(包括所有拥塞状态)以及pacing rate的设置
	 * 用BBR的主要函数, 取代了传统的cong_avoid接口
	 */
	.cong_control	= bbr_main,
	/* 该接口控制发送缓存的扩展倍数, TCP默认为2倍, BBR设置为3倍 */
	.sndbuf_expand	= bbr_sndbuf_expand,
	.undo_cwnd	= bbr_undo_cwnd, /* BBR undo时不修改拥塞窗口 */
	.cwnd_event	= bbr_cwnd_event,
	.ssthresh	= bbr_ssthresh, /* 仅保存cwnd值, BBR不使用慢启动阈值 */
	/* 该接口用于控制TSO段的大小, 返回0表示默认自动处理 */
	.tso_segs_goal	= bbr_tso_segs_goal,
	.get_info	= bbr_get_info, /* 用于getsockopt获取拥塞算法的信息 */
	.set_state	= bbr_set_state, /* 处理进入LOSS状态 */
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
