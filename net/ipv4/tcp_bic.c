/*
 * Binary Increase Congestion control for TCP
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of BICTCP in
 * Lison-Xu, Kahaled Harfoush, and Injong Rhee.
 *  "Binary Increase Congestion Control for Fast, Long Distance
 *  Networks" in InfoComm 2004
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/bitcp.pdf
 *
 * Unless BIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>


#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */

static int fast_convergence = 1; /*  BIC能快速的达到一个平衡值，开关 */
				 /* 设置了fast_convergence在丢包后，该连接会过早的达到一个平衡值，为0.9*snd_cwnd */
static int max_increment = 16; 	/* 每次增加的MSS 不能超过这个值，防止增长太过剧烈 */
static int low_window = 14; 	/* 拥塞窗口下界 */
static int beta = 819;		/* 丢包后的慢启动阈值。为 819/1024 = 0.8 (BICTCP_BETA_SCALE) */
static int initial_ssthresh; 	/* 初始的阈值, 默认为7FFFFFFF */
static int smooth_part = 20; 	/* 代表平稳阶段持续的RTT。这个值越大，则把窗口维持在last_max_cwnd的时间就越长 */

module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(max_increment, int, 0644);
MODULE_PARM_DESC(max_increment, "Limit on increment allowed during binary search");
module_param(low_window, int, 0644);
MODULE_PARM_DESC(low_window, "lower bound on congestion window (for TCP friendliness)");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(smooth_part, int, 0644);
MODULE_PARM_DESC(smooth_part, "log(B/(B*Smin))/log(B/(B-1))+B, # of RTT from Wmax-B to Wmax");


/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	epoch_start;	/* beginning of an epoch */
#define ACK_RATIO_SHIFT	4
	u32	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);
	ca->loss_cwnd = 0;

	if (initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	/* 31.25ms以内不更新ca */
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

	if (ca->epoch_start == 0) /* record the beginning of an epoch */
		ca->epoch_start = tcp_time_stamp;

	/* start off normal */
	/* 为了保持友好性, 这样14个以内的ack，可使snd_cwnd++ */
	if (cwnd <= low_window) { 
		ca->cnt = cwnd;
		return;
	}

	/* binary increase */
	if (cwnd < ca->last_max_cwnd) { /* Searching阶段 */
		__u32 	dist = (ca->last_max_cwnd - cwnd)
			/ BICTCP_B; 	/* 四分之一 */

		if (dist > max_increment) /* dist > 16，即 last_max_cwnd - cwnd > 64 */
			/* linear increase */
			ca->cnt = cwnd / max_increment; /* 每个RTT cwnd增加16 */
		else if (dist <= 1U) /* dist <= 1, 即 0 < last_max_cwnd - cwnd <= 4 */
			/* binary search increase */
			/*  ca->cnt=5*cwnd，会造成snd_cwnd增长极其缓慢，即处于稳定阶段 */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B; /* 经过5个RTT，cwnd增加1个 */
		else 	/* 1 < dist <= 16，即 4 <　last_max_cwnd -cwnd <= 64 */
			/* binary search increase */
			ca->cnt = cwnd / dist;  /* 每个RTT内，cwnd增加(last_max_cwnd-cwnd)/4个  */
	} else { /* max_probing阶段 */
		/* slow start AMD linear increase */
		if (cwnd < ca->last_max_cwnd + BICTCP_B) /* last_max_cwnd < cwnd < last_max_cwnd + 4 */
			/* slow start */
			ca->cnt = (cwnd * smooth_part) / BICTCP_B; /* 经过5个RTT，cwnd增加1个 */
		else if (cwnd < ca->last_max_cwnd + max_increment*(BICTCP_B-1)) 
			/* last_max_cwnd + 4 < cwnd < last_max_cwnd+48 */
			/* slow start */
			/* 每个RTT内，cwnd增加(cwnd-last_max_cwnd)/3 */
			/* 增长率从5/(3*cwnd)~47/(3*cwnd)，snd_cwnd的增长加快 */
			ca->cnt = (cwnd * (BICTCP_B-1))
				/ (cwnd - ca->last_max_cwnd);
		else 	/* cwnd >= last_max_cwnd+48 */
			/* linear increase */
			ca->cnt = cwnd / max_increment; /* 每个RTT内，cwnd增加16个 */
	}

	/* if in slow start or link utilization is very low */
	if (ca->last_max_cwnd == 0) { /* 没有发生过丢包，所以snd_cwnd增长应该快点 */
		if (ca->cnt > 20) /* increase cwnd 5% per RTT */
			ca->cnt = 20;
	}

	/* 相当于乘与delayed_ack的百分比，delayed得越严重，则snd_cwnd应该增加越快
	 * 这样有无delayed对snd_cwnd的影响不大
	 */
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	/*  如果发送拥塞窗口不被限制，不能再增加，则返回 */
	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* 如果拥塞窗口小于阈值，则慢启动 */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);
	else {
		bictcp_update(ca, tp->snd_cwnd); /* BIC算法关键 */
		tcp_cong_avoid_ai(tp, ca->cnt);  
	}

}

/*
 *	behave like Reno until low_window is reached,
 *	then increase congestion window slowly
 */
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	/* 丢包点比上次低，说明恶化，则主动降低 */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		/* last_max_cwnd = 0.9*cwnd */
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else	/* 丢包点比上次高，则说明更好，当然采用更大的 */
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;


	if (tp->snd_cwnd <= low_window) /* snd_cwnd<=14时，snd_ssthresh = snd_cwnd/2, 同reno，保持友好性 */
		return max(tp->snd_cwnd >> 1U, 2U);
	else	/* 就是snd_ssthresh=0.8*snd_cwnd ，很大的一个数，能充分利用带宽 */
		return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 bictcp_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct bictcp *ca = inet_csk_ca(sk);
	return max(tp->snd_cwnd, ca->loss_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss)
		bictcp_reset(inet_csk_ca(sk));
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
static void bictcp_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_state == TCP_CA_Open) {
		struct bictcp *ca = inet_csk_ca(sk);
		cnt -= ca->delayed_ack >> ACK_RATIO_SHIFT; /* 作者似乎很注重delayed包对snd_cwnd的影响，要尽量削弱 */
		ca->delayed_ack += cnt;
	}
}


static struct tcp_congestion_ops bictcp = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "bic",
};

static int __init bictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&bictcp);
}

static void __exit bictcp_unregister(void)
{
	tcp_unregister_congestion_control(&bictcp);
}

module_init(bictcp_register);
module_exit(bictcp_unregister);

MODULE_AUTHOR("Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BIC TCP");
