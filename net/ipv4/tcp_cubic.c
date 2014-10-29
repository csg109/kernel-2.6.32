/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.3
 * Home page:
 *      http://netsrv.csc.ncsu.edu/twiki/bin/view/Main/BIC
 * This is from the implementation of CUBIC TCP in
 * Sangtae Ha, Injong Rhee and Lisong Xu,
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant"
 *  in ACM SIGOPS Operating System Review, July 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/cubic_a_new_tcp_2008.pdf
 *
 * CUBIC integrates a new slow start algorithm, called HyStart.
 * The details of HyStart are presented in
 *  Sangtae Ha and Injong Rhee,
 *  "Taming the Elephants: New TCP Slow Start", NCSU TechReport 2008.
 * Available from:
 *  http://netsrv.csc.ncsu.edu/export/hystart_techreport_2008.pdf
 *
 * All testing results are available from:
 * http://netsrv.csc.ncsu.edu/wiki/index.php/TCP_Testing
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <net/tcp.h>

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)

static int fast_convergence __read_mostly = 1;	/* 快速收敛 */
static int beta __read_mostly = 717;		/* 1-乘法减小因子, 0.7= 717/1024 */
static int initial_ssthresh __read_mostly;	/* 可设置慢启动阈值，只有hystart未启动才有效 */
static int bic_scale __read_mostly = 41; 	/* 即论文中的常数C，值为0.4 = 41*10/1024 */
static int tcp_friendliness __read_mostly = 1;	/* 友好性，当cubic增长比reno慢时使用reno的增长 */
static int hystart __read_mostly = 1; 		/* 混合启动开关 */

/* HyStart状态描述
 * 1：packet-train, 即ack-train
 * 2：delay
 * 3：both packet-train and delay
 * 默认2种方法都使用，即设为3
 */
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16; /* 除非cwnd超过了这个值，才能使用HyStart */
static int hystart_ack_delta __read_mostly = 2;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hyrbrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta, "spacing between ack's indicating train (msecs)");

/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
				/* 用于控制snd_cwnd增长速度 */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
				/* 上一次丢包时的cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
				/* 上次丢包时的cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
				/* 记录上一次更新时的拥塞窗口 */
	u32	last_time;	/* time when updated last_cwnd */
				/* 记录上一次更新时的时间点，与last_cwnd一起控制更新的频率 */
	u32	bic_origin_point;/* origin point of bic function */
				/* 即新的Wmax，取last_max_cwnd和snd_cwnd大者 */
	u32	bic_K;		/* time to origin point from the beginning of the current epoch */
				/* 即新Wmax所对应的时间(增长函数中的K)，W(bic_K) = Wmax */
	u32	delay_min;	/* min delay (msec << 3) */
				/* 左移3位后(扩大8倍)的最小RTT */
	u32	epoch_start;	/* beginning of an epoch */
				/* 记录丢包后的这个新时段开始的时间点 */
	u32	ack_cnt;	/* number of acks */
				/* 记录丢包后的这个新时段内的收到的ack个数, 用于计算Reno的cwnd */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
				/* 按照Reno算法计算得的cwnd */
#define ACK_RATIO_SHIFT	4
#define ACK_RATIO_LIMIT (32u << ACK_RATIO_SHIFT)
	u16	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
				/* 为了消除delay ACK的影响 */
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
				/* Hystart的delay-increase使用， 用来标记每个RTT的第几个sample */
	u8	found;		/* the exit point is found?  1：yes，0：no */
				/* Hystart使用， 标记混合启动时退出慢启动点是否找到; 低两位分别对应找到退出点的算法HYSTART_ACK_TRAIN或者HYSTART_DELAY */
	u32	round_start;	/* beginning of each round */
				/* Hystart的ack-train使用，标记每个RTT开始的时间点 */
	u32	end_seq;	/* end_seq of the round */
				/* Hystart使用，用来标识每个RTT的结束点 */
	u32	last_ack;	/* last time when the ACK spacing is close */
				/* Hystart的ack-train使用，用于记录一个RTT中ack-train中最后ack收到的时间，超过2ms则认为是不连续的 */
	u32	curr_rtt;	/* the minimum rtt of current round */
				/* Hystart的delay-increase使用,记录每个RTT的sampe中最小RTT(扩大8倍) */
};

static inline void bictcp_reset(struct bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}

static inline u32 bictcp_clock(void)
{
#if HZ < 1000
	return ktime_to_ms(ktime_get_real());
#else
	return jiffies_to_msecs(jiffies);
#endif
}

/* bictcp_hystart_reset中并没有对ca->found置0。
 * 也就是说，只有在一开始或者丢包时，HyStart才会派上用场，其它时间并不使用。
 */
static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock(); /*  记录每个RTT开始的时间点和最后ACK的时间点 */
	ca->end_seq = tp->snd_nxt; /* 标志本RTT的结束点 */
	ca->curr_rtt = 0;	/* 初始化本轮RTT中取自样本的RTT值 */
	ca->sample_cnt = 0;	/* 初始化本轮RTT中样本个数 */
}

static void bictcp_init(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);
	ca->loss_cwnd = 0;

	if (hystart)
		bictcp_hystart_reset(sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
/* 计算立方根 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * Compute congestion window to use.
 */
/* cubic关键算法 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	u64 offs;	/*  时间差，| t - K | */
	u32 delta, t, bic_target, max_cnt; /* delta是cwnd差，bic_target是预测值，t为预测时间 */

	ca->ack_cnt++;	/* count the number of ACKs *//* 增加这个时段内收到ack的个数 */

	/* 31.25ms以内不更新ca */
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

	/* 以下是按照增长函数公式计算一个RTT后的预期窗口大小 W(t+RTTmin) = C(t+RTTmin - K)^3 + Wmax
	 * 其中:
	 * 	C为cube_rtt_scale 
	 * 	RTTmin为delay_min>>3，即计算RTTmin之后的窗口大小
	 * 	K为bic_K,在每次丢包后的新的阶段中计算
	 * 	Wmax为bic_origin_point
	 */

	/* 丢包后 一个新的时段，这里计算K的值bic_K以及Wmax的值bic_origin_point */
	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_time_stamp;	/* record the beginning of an epoch *//* 记录时间点 */
		ca->ack_cnt = 1;			/* start counting *//* 重置收到ack的个数 */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		/* 取max(last_max_cwnd , cwnd)作为当前Wmax */
		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else { /* last_max_cwnd > cwnd */
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			/* bic_K本来单位为秒，转成单位为 1 / 1024秒 */
			/* 计算bic_K = cubic_root(1/C * (Wmax-cwnd)), 单位为1/2024 HZ; cube_factor为1/C */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	/* c = bic_scale >> 10 = 0.04 
	 * Constant = c / srtt = 0.4, 实际参数为0.4 
	 */

	/* change the unit from HZ to bictcp_HZ */
	/* 预测时间为t+RTT：即ca->delay_min >> 3后 */
	t = ((tcp_time_stamp + msecs_to_jiffies(ca->delay_min>>3)
	      - ca->epoch_start) << BICTCP_HZ) / HZ;

	/* 计算| t - bic_K | */
	if (t < ca->bic_K) /* 还未达到Wmax */		/* t - K */
		offs = ca->bic_K - t;
	else	/* 此时已经超过Wmax */
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	/* 计算 delta = | W(t) - W(bic_K) |  
	 * cube_rtt_scale = (bic_scale * 10) = c / srtt * 2^10，c/srtt = 0.4 
	 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ); /* delta = |C*(t-K)^3| */
	
	/* 计算bic_target，即预测W(t+RTT)*/
	if (t < ca->bic_K) /* 还未达到Wmax */ /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                                	/* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	/* 计算完W(t+RTT),则将W(t+RTT)与cwnd对比，确定cnt */
	if (bic_target > cwnd) {
		/* 相差越多，增长越快 */
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		/* 目前cwnd已经超出预期了，应该降速 */
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	/* 一些因素会导致HyStart的提前退出，从而不能充分利用可用带宽。
	 * 实际上HyStart的测量结果很可能会偏小。
	 * 所以当退出HyStart后，进入拥塞避免状态时，如果发现之前没有丢包过，并且cwnd的增长幅度小于5%，
	 * 那么就把cwnd每RTT的增长幅度调整为5%。
	 * 这样一来如果前提退出慢启动时，保证拥塞窗口的增速不会太低。*/
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

	/* TCP Friendly */
	/*  TCP Friendly —如果bic比RENO慢， 则提高cwnd增长速度，即减小cnt 
	 *  以上次丢包以后的时间t算起，每次RTT增长 3B / ( 2 - B)，那么可以得到 
	 *  采用RENO算法的cwnd。 
	 *  cwnd (RENO) = cwnd + 3B / (2 - B) * ack_cnt / cwnd 
	 *  B为乘性减少因子，在此算法中为0.3 
	 */
	if (tcp_friendliness) {
		u32 scale = beta_scale; 
		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd){	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* 消除delay ACK的影响, 如果有delay ACK, 则cnt会进一步调整变小，cwnd增加 */
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack; 

	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}

static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* 如果拥塞窗口小于阈值，则慢启动 */
	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		if (hystart && after(ack, ca->end_seq)) /* 一个RTT结束了，开始新的一个RTT */
			bictcp_hystart_reset(sk);
		tcp_slow_start(tp);
	} else { /* 拥塞避免 */
		bictcp_update(ca, tp->snd_cwnd);
		tcp_cong_avoid_ai(tp, ca->cnt);
	}

}

static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch *//* 结束上一个丢包的时段 */

	/* Wmax and fast convergence */
	/* 丢包点比上次低，说明恶化，则主动降低 */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		/* last_max_cwnd = 0.85*cwnd */
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else	/* 丢包点比上次高，则说明更好，当然采用更大的 */
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;

	/* 新的阈值为0.7*snd_cwnd */
	return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 bictcp_undo_cwnd(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(sk); /* LOSS状态重新进入慢启动，所以要重新启动Hystart, found变量在bictcp_reset()中重置为0 */
	}
}

/* hystart混合启动关键算法 */
static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!(ca->found & hystart_detect)) { /* 启动hystart且exit point还没找到 */
		u32 now = bictcp_clock(); /* 毫秒级时间 */

		/* first detection parameter - ack-train detection */
		/* 第一种探测：ack-train */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta) { /* 距离上个ACK包2ms内才算连续的ack-train */
			ca->last_ack = now;
			/* ack-train的思想是:
			 * ack-train中一系列的ack中第一个ack与最后一个ack时间距离大于时延(1/2的最小RTT)，则认为是exit point.
			 * 这里round_start即为本RTT内第一个ack的时间点，delay_min为左移3位后的最小RTT，右移4位即1/2的RTTmin
			 */
			if ((s32)(now - ca->round_start) > ca->delay_min >> 4)
				ca->found |= HYSTART_ACK_TRAIN; /* ack-train判断为慢启动退出点 */
		}

		/* obtain the minimum delay of more than sampling packets */
		/* 这里为第二种探测：delay-increase */
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) { /* 每个RTT的前8个ACK为样本, 记录样本中最小的RTT为本次的RTT*/
			if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
				ca->curr_rtt = delay; /* 注意，此时的delay还是扩大8倍后的值 */

			ca->sample_cnt++;
		} else { /* 记录样本之后，如果本次RTT(取自RTT的前8个样本)大于最小RTT+n(n为调整阈值), 则认为exit point */
			/* 注意：此时curr_rtt和delay_min都是扩大8倍后的，而HYSTART_DELAY_THRESH的参数时延的单位为ms
			 * 所以实际上限制的为4-16ms
			 */
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min>>4))
				ca->found |= HYSTART_DELAY; /* delay-increase找到退出点 */
		}
		/*
		 * Either one of two conditions are met,
		 * we exit from slow start immediately.
		 */
		/* 找到了退出点，调整慢启动阈值退出慢启动进入拥塞避免 */
		if (ca->found & hystart_detect)
			tp->snd_ssthresh = tp->snd_cwnd;
	}
}

/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
static void bictcp_acked(struct sock *sk, u32 cnt, s32 rtt_us)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u32 delay;	/* 此次的RTT  */

	/* 这里计算delayed_ack变量，如果本次ack的包个数不止一个,则delayed_ack变大，
	 * 之后该变量在bictcp_update()中用来消除delay ACK的影响
	 */
	if (icsk->icsk_ca_state == TCP_CA_Open) {
		u32 ratio = ca->delayed_ack;

		ratio -= ca->delayed_ack >> ACK_RATIO_SHIFT;
		ratio += cnt;

		ca->delayed_ack = min(ratio, ACK_RATIO_LIMIT);
	}

	/* Some calls are for duplicates without timetamps */
	if (rtt_us < 0)
		return;

	/* Discard delay samples right after fast recovery */
	/* 在快速恢复后1s内不进行采样 */
	if ((s32)(tcp_time_stamp - ca->epoch_start) < HZ)
		return;

	/*  rtt_us这里扩大8倍，计算的时候会缩小8倍 */
	delay = (rtt_us << 3) / USEC_PER_MSEC;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	/* 开启混合启动后，处于慢启动阶段并且cwnd大于混合启动最小窗口，进行混合启动处理 */
	if (hystart && tp->snd_cwnd <= tp->snd_ssthresh &&
	    tp->snd_cwnd >= hystart_low_window)
		hystart_update(sk, delay);
}

static struct tcp_congestion_ops cubictcp = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "cubic",
};

static int __init cubictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */
	/* beta_scale = 8*(1024 + 717) / 3 / (1024 -717 )，大约为15  */
	beta_scale = 8*(BICTCP_BETA_SCALE+beta)/ 3 / (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	/* do_div() 除法运算，结果保存在x中，余数保存在返回值中。*/
	/* cube_factor是用来计算bic_K的（论文中的K）:
	 * bic_K = cubic_root( Wmax*beta)/C ) = cubic_root( Wlast_max - cwnd) / C)
	 * 为了计算bic_K,这里需要得到1/C的值，即令cube_factor=1/C
	 * 而论文中C的值为0.4:  C = (bic_scale*10)/(2^10) 
	 * 所以，cube_factor = 1/C = 1/((bic_scale*10)/(2^10)) = (2^10)/(bic_scale*10)
	 *
	 * 另外，为了提高精度，时间放大BICTCP_HZ倍，即2^10倍，而后面计算bic_K有立方根的计算，
	 * 所以上面cube_factor初始化时才在2^10的基础上多了3*BICTCP_HZ倍，
	 * 即1 << (10 + 3*BICTCP_HZ) = 2^10 * 2^(3*BICTCP_HZ)
	 */
	do_div(cube_factor, bic_scale * 10);

	/* hystart needs ms clock resolution */
	if (hystart && HZ < 1000)
		cubictcp.flags |= TCP_CONG_RTT_STAMP;

	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CUBIC TCP");
MODULE_VERSION("2.3");
