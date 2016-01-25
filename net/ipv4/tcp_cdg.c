/*
 * CAIA Delay-Gradient (CDG) congestion control
 *
 * This implementation is based on the paper:
 *   D.A. Hayes and G. Armitage. "Revisiting TCP congestion control using
 *   delay gradients." In IFIP Networking, pages 328-341. Springer, 2011.
 *
 * Scavenger traffic (Less-than-Best-Effort) should disable coexistence
 * heuristics using parameters use_shadow=0 and use_ineff=0.
 *
 * Parameters window, backoff_beta, and backoff_factor are crucial for
 * throughput and delay. Future work is needed to determine better defaults,
 * and to provide guidelines for use in different environments/contexts.
 *
 * Except for window, knobs are configured via /sys/module/tcp_cdg/parameters/.
 * Parameter window is only configurable when loading tcp_cdg as a module.
 *
 * Notable differences from paper/FreeBSD:
 *   o Using Hybrid Slow start and Proportional Rate Reduction.
 *   o Add toggle for shadow window mechanism. Suggested by David Hayes.
 *   o Add toggle for non-congestion loss tolerance.
 *   o Scaling parameter G is changed to a backoff factor;
 *     conversion is given by: backoff_factor = 1000/(G * window).
 *   o Limit shadow window to 2 * cwnd, or to cwnd when application limited.
 *   o More accurate e^-x.
 */
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/module.h>
#include <net/tcp.h>

#define HYSTART_ACK_TRAIN	1
#define HYSTART_DELAY		2

/* 梯度的窗口大小，即paper中的a值
 * 必须设置为[1, 256], 并且为2的整次幂 
 */
static int window __read_mostly = 8; 

/* 乘法因子beta, 控制梯度退避的窗口减小比例，默认为0.7 */
static unsigned int backoff_beta __read_mostly = 0.7071 * 1024; /* sqrt 0.5 */

/* backoff_factor相当于paper中的G参数，
 * 转换公式为：backoff_factor = 1000/(G * window)
 * 所以backoff_factor为42相当于G为3
 */
static unsigned int backoff_factor __read_mostly = 42;

/* hystart的开关，包括HYSTART_ACK_TRAIN和HYSTART_DELAY */
static unsigned int hystart_detect __read_mostly = 3;

/* 无效梯度退避的阈值，
 * 当连续退避无效use_ineff次后就不再使用梯度退避,
 * 即paper中的b参数
 */
static unsigned int use_ineff __read_mostly = 5;

/* 影子窗口开关
 * 开启后模拟NewReno的窗口增长，
 * 然后在丢包时，使用该值来减少窗口，回补之前梯度退避损失的窗口
 */
static bool use_shadow __read_mostly = true;

/* tolerance策略的开关, 默认是关闭的。
 * 开启后，会判断路由队列状态是否满，
 * 以此来推断丢包是否为拥塞窗口，如果为随机丢包则不需要减小拥塞窗口
 */
static bool use_tolerance __read_mostly;

module_param(window, int, 0444);
MODULE_PARM_DESC(window, "gradient window size (power of two <= 256)");
module_param(backoff_beta, uint, 0644);
MODULE_PARM_DESC(backoff_beta, "backoff beta (0-1024)");
module_param(backoff_factor, uint, 0644);
MODULE_PARM_DESC(backoff_factor, "backoff probability scale factor");
module_param(hystart_detect, uint, 0644);
MODULE_PARM_DESC(hystart_detect, "use Hybrid Slow start "
		 "(0: disabled, 1: ACK train, 2: delay threshold, 3: both)");
module_param(use_ineff, uint, 0644);
MODULE_PARM_DESC(use_ineff, "use ineffectual backoff detection (threshold)");
module_param(use_shadow, bool, 0644);
MODULE_PARM_DESC(use_shadow, "use shadow window heuristic");
module_param(use_tolerance, bool, 0644);
MODULE_PARM_DESC(use_tolerance, "use loss tolerance heuristic");

struct minmax {
	union {
		struct {
			s32 min;
			s32 max;
		};
		u64 v64;
	};
};

/* 状态 */
enum cdg_state {
	CDG_UNKNOWN = 0, /* 默认状态 */
	CDG_NONFULL = 1, /* 排队队列未满 */
	CDG_FULL    = 2, /* 排队队列满 */
	CDG_BACKOFF = 3, /* 梯度退避状态 */
};

/* cdg主要结构体，已经用满了icsk的64字节 */
struct cdg {
	struct minmax rtt;		/* 本次RTT周期的RTT */
	struct minmax rtt_prev; 	/* 记录上一个RTT周期的RTT */
	struct minmax *gradients;	/* gradients数组分配了window个RTT值，
					   记录了window内的所有g(n),包括g(max,n)和g(min,n) */
	struct minmax gsum;		/* gsum累加了所有 g(n) - g(n-window), 直接表示梯度G(n) */
	bool gfilled;			/* 用来标记刚开始采集时，gradients数组是否已经填满window个 */
	u8  tail;			/* gradients数组的索引 */
	u8  state;	/* 状态, 由cdg_state定义 */
	u8  delack;	/* 记录delay ack的个数 */
	u32 rtt_seq; 	/* 记录snd_nxt, 用于判断标记一个RTT周期 */
	u32 undo_cwnd;	/* 用于拥塞撤销,保存丢包时的拥塞窗口 */
	u32 shadow_wnd; /* 影子窗口, 用来模拟NewReno窗口的增长, 在丢包时使用该值来回补之前由于梯度退避损失的窗口 */
	u16 backoff_cnt;/* 记录连续梯度退避的次数，如果退避次数超过use_ineff,则认为退避无效不再退避 */
	u16 sample_cnt;	/* Hystart的delay-increase使用, 用来标记每个RTT的第几个sample */
	s32 delay_min;	/* Hystart使用，记录最小RTT */
	u32 last_ack; 	/* Hystart的ack-train使用，用于记录一个RTT中ack-train中最后ack收到的时间，超过3ms则认为是不连续的 */
	u32 round_start;/* Hystart的ack-train使用，标记每个RTT周期开始的时间点 */
};

/**
 * nexp_u32 - negative base-e exponential
 * @ux: x in units of micro
 *
 * Returns exp(ux * -1e-6) * U32_MAX.
 */
static u32 __pure nexp_u32(u32 ux)
{
	/* v数组为 e(-x) * 65536 -1 的经验值，e(-x)为e的-x次幂,
	 * 其中x为0, 0.000256, 0.000512, 0.001024 ... 
	 */
	static const u16 v[] = {
		/* exp(-x)*65536-1 for x = 0, 0.000256, 0.000512, ... */
		65535,
		65518, 65501, 65468, 65401, 65267, 65001, 64470, 63422,
		61378, 57484, 50423, 38795, 22965, 8047,  987,   14,
	};
	u32 msb = ux >> 8;
	u32 res;
	int i;

	/* Cut off when ux >= 2^24 (actual result is <= 222/U32_MAX). */
	if (msb > U16_MAX)
		return 0;

	/* Scale first eight bits linearly: */
	res = U32_MAX - (ux & 0xff) * (U32_MAX / 1000000);

	/* Obtain e^(x + y + ...) by computing e^x * e^y * ...: */
	for (i = 1; msb; i++, msb >>= 1) {
		u32 y = v[i & -(msb & 1)] + U32_C(1);

		res = ((u64)res * y) >> 16;
	}

	return res;
}

/* Based on the HyStart algorithm (by Ha et al.) that is implemented in
 * tcp_cubic. Differences/experimental changes:
 *   o Using Hayes' delayed ACK filter.
 *   o Using a usec clock for the ACK train.
 *   o Reset ACK train when application limited.
 *   o Invoked at any cwnd (i.e. also when cwnd < 16).
 *   o Invoked only when cwnd < ssthresh (i.e. not when cwnd == ssthresh).
 */
static void tcp_cdg_hystart_update(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* 采集最小RTT */
	ca->delay_min = min_not_zero(ca->delay_min, ca->rtt.min);
	if (ca->delay_min == 0)
		return;

	/* ack-train探测, ack-train的思想是:
	 * ack-train中一系列的ack中第一个ack与最后一个ack时间距离大于单向时延(1/2的最小RTT)，则认为是exit point.
	 */
	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now_us = div_u64(local_clock(), NSEC_PER_USEC); /* 当前时刻，纳秒转为微秒 */

		if (ca->last_ack == 0 || !tcp_is_cwnd_limited(sk)) { /* 每个RTT周期开始或者应用层限制时，开始新的探测周期 */
			ca->last_ack = now_us;
			ca->round_start = now_us;
		} else if (before(now_us, ca->last_ack + 3000)) { /* 距离上个ACK包3ms内才算连续的ack-train */
			u32 base_owd = max(ca->delay_min / 2U, 125U); /* 单向时延，即1/2 minRTT, 限制最小值为125微秒 */

			ca->last_ack = now_us; /* 更新最后ACK时间 */

	 		/* 这里round_start为本RTT内第一个ack的时间点，
			 * 满足条件则说明需要退出慢启动
			 */
			if (after(now_us, ca->round_start + base_owd)) {
				NET_INC_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTTRAINCWND,
						 tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd; /* 进入拥塞避免 */
				return;
			}
		}
	}

	/* delay-increase, 核心思想是：
	 * 如果本个RTT周期采集的RTT样本(取前8个样本的最小值)大于连接最小RTT(delay_min) + n(n为调整阈值), 则认为exit point
	 */
	if (hystart_detect & HYSTART_DELAY) {
		if (ca->sample_cnt < 8) { /* 每个RTT的前8个ACK为样本, 记录样本中最小的RTT为本次的RTT, 
					   *记录由ca->rtt.min记录, 所以这里不再记录
					   */
			ca->sample_cnt++;
		} else {
			/* 调整阈值n为 1+1/8 delay_min, 限制最小值为125微秒 */
			s32 thresh = max(ca->delay_min + ca->delay_min / 8U,
					 125U);

			/* RTTsimple > max(1+1/8 RTTmin, 125US) , 满足条件则退出慢启动*/
			if (ca->rtt.min > thresh) {
				NET_INC_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTDELAYCWND,
						 tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd; /* 进入拥塞避免 */
			}
		}
	}
}

static s32 tcp_cdg_grad(struct cdg *ca)
{
	s32 gmin = ca->rtt.min - ca->rtt_prev.min; /* 计算本轮RTTmin的增量g(min,n) */
	s32 gmax = ca->rtt.max - ca->rtt_prev.max; /* 计算本轮RTTmax的增量g(max,n) */
	s32 grad; /* 梯度G(n) */

	/* 计算移动平均线G(n)时，paper提供迭代公式(4)计算梯度G(n):
	 * 	G(n) = G(n-1) + ( g(n) - g(n-window) ) / window
	 *
	 * 但是，实现与paper有差异，我们并没有除以window值，即简化为：
	 * 	G(n) = G(n-1) + ( g(n) - g(n-window) )
	 *
	 * 以下的gsum即为G(n)
	 */
	if (ca->gradients) {
		/* gsum累加了所有 g(n) - g(n-window) */
		ca->gsum.min += gmin - ca->gradients[ca->tail].min;
		ca->gsum.max += gmax - ca->gradients[ca->tail].max;
		/* gradient数组记录了window内的所有g(n),包括g(max,n)和g(min,n) */
		ca->gradients[ca->tail].min = gmin;
		ca->gradients[ca->tail].max = gmax;
		/* gradient数组索引递增 */
		ca->tail = (ca->tail + 1) & (window - 1);
		/* 现在取出gsum的值 */
		gmin = ca->gsum.min;
		gmax = ca->gsum.max;
	}

	/* We keep sums to ignore gradients during cwnd reductions;
	 * the paper's smoothed gradients otherwise simplify to:
	 * (rtt_latest - rtt_oldest) / window.
	 *
	 * We also drop division by window here.
	 */
	/* 梯度grad如果gmin大于0,则取gmin，否则取gmax */
	grad = gmin > 0 ? gmin : gmax;

	/* Extrapolate missing values in gradient window: */
	/* 处理刚开始采集时window内的数据还未满的情况 */
	if (!ca->gfilled) { 
		if (!ca->gradients && window > 1)
			grad *= window; /* Memory allocation failed. */
		else if (ca->tail == 0)
			/* window数据填满，即采集了window个RTT的数据了 */
			ca->gfilled = true; 
		else
			/* 当刚开始采集的数据没填满window时, G(n)需要做点处理 */
			grad = (grad * window) / (int)ca->tail;
	}

	/* Backoff was effectual: */
	/* 梯度退避之后,G(min,n)或者G(max,n)为负数，说明退避是有效果的，
	 * 那么清空无效退避计数
	 */
	if (gmin <= -32 || gmax <= -32)
		ca->backoff_cnt = 0;

	/* 如果使用了tolerance, 则会判断当前的排队队列的状态(队列满或者未满)
	 * 在丢包时就可以用来判断是否为拥塞丢包, 如果非拥塞丢包就不用减小拥塞窗口
	 */
	if (use_tolerance) {
		/* Reduce small variations to zero: */
		/* 除以64，为了增加精度 */
		gmin = DIV_ROUND_CLOSEST(gmin, 64);
		gmax = DIV_ROUND_CLOSEST(gmax, 64);

		/* RTTmax已经不在增大，而RTTmin还在持续增大，说明排队队列满了, 状态切换为FULL */
		if (gmin > 0 && gmax <= 0)
			ca->state = CDG_FULL;
		/* 两个条件都能说明队列非满，状态切换为NOFULL:
		 * 1.RTTmin和RTTmax都在持续增大，说明队列中的数据包越来越大，但是还没满
		 * 2. RTTmax已经持续地减小，说明队列从满的状态开始变为未满的状态
		 */
		else if ((gmin > 0 && gmax > 0) || gmax < 0)
			ca->state = CDG_NONFULL;
	}
	return grad;
}

static bool tcp_cdg_backoff(struct sock *sk, u32 grad)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* 根据梯度值grad计算梯度退避概率，
	 * 然后与随机值进行比较来决定是否进行梯度退避
	 *
	 * paper中退避概率P的计算公式为：
	 * 	P[backoff] = 1 - e^(-(G(n)/G))
	 * 	其中G(n)即梯度值grad, 参数G可转化为backoff_factor,转化公式为 backoff_factor = 1000/(G * window) 
	 *
	 * nexp_u32()计算概率公式并把[0, 1]的概率值转成32位值便于跟prandom_u32()返回的随机值比较
	 */
	if (prandom_u32() <= nexp_u32(grad * backoff_factor))
		return false;

	/* 这是paper中的ineffectual backoff detection
	 * 原理是当梯度退避use_ineff次后，gmin和gmax还是非负, 
	 * 那说明我们退避的无效的，因为我们在跟基于丢包的拥塞算法竞争，
	 * 所以我们不再使用梯度退避
	 */
	if (use_ineff) {
		ca->backoff_cnt++;
		if (ca->backoff_cnt > use_ineff)
			return false;
	}

	ca->shadow_wnd = max(ca->shadow_wnd, tp->snd_cwnd); /* 退避时记录影子窗口 */
	ca->state = CDG_BACKOFF; /* 设置退避状态，在退出CWR状态时会重置为CDG_UNKNOWN */

	/* 梯度退避直接进入CWR状态， 
	 * tcp_enter_cwr()会调用tcp_cdg_ssthresh()使用乘法因子减小
	 */
	tcp_enter_cwr(sk);
	return true;
}

/* Not called in CWR or Recovery state. */
static void tcp_cdg_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 prior_snd_cwnd;
	u32 incr;

	/* 慢启动时使用hystart检测是否需要退出慢启动 */
	if (tcp_in_slow_start(tp) && hystart_detect)
		tcp_cdg_hystart_update(sk);

	/* 每个RTT周期使用梯度来检测是否拥塞 */
	if (after(ack, ca->rtt_seq) && ca->rtt.v64) {
		s32 grad = 0;	/* 用于保存计算的梯度 */

		if (ca->rtt_prev.v64) 		/* 第二轮RTT周期才开始计算梯度 */
			grad = tcp_cdg_grad(ca);/* 调用梯度算法得到梯度值 */
		ca->rtt_seq = tp->snd_nxt; 	/* 记录下一个RTT周期 */
		ca->rtt_prev = ca->rtt; 	/* 保存前一个RTT周期的RTT */
		ca->rtt.v64 = 0; 		/* 本次RTT清零 */
		ca->last_ack = 0; 		/* hystart的最后ACK时间清零 */
		ca->sample_cnt = 0; 		/* hystart的样本数清零 */

		/* 如果上面得到的梯度值大于0，说明可能需要拥塞退避。
		 * tcp_cdg_backoff()中会计算退避概率，命中时进行退避
		 */
		if (grad > 0 && tcp_cdg_backoff(sk, grad))
			return;
	}

	/* 这里是跟paper有区别：
	 * 当应用层限制时，调整影子窗口为不超过拥塞窗口
	 */
	if (!tcp_is_cwnd_limited(sk)) {
		ca->shadow_wnd = min(ca->shadow_wnd, tp->snd_cwnd);
		return;
	}

	prior_snd_cwnd = tp->snd_cwnd;
	tcp_reno_cong_avoid(sk, ack, acked); /* 调用reno接口增加拥塞窗口 */

	/* 影子窗口会同步回补窗口的增量，这就是paper中的lost transmission opportunities */
	incr = tp->snd_cwnd - prior_snd_cwnd; /* 拥塞窗口增量 */
	ca->shadow_wnd = max(ca->shadow_wnd, ca->shadow_wnd + incr);
}

static void tcp_cdg_acked(struct sock *sk, u32 num_acked, s32 rtt_us)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (rtt_us <= 0)
		return;

	/* A heuristic for filtering delayed ACKs, adapted from:
	 * D.A. Hayes. "Timing enhancements to the FreeBSD kernel to support
	 * delay and rate based TCP mechanisms." TR 100219A. CAIA, 2010.
	 */
	/* 这里排除delay ack对RTT的影响：
	 * 在没有SACK时,
	 * 出现delay ack(一次确认超过一个段)时，记录delay ack的个数n(n<5),
	 * 然后在接下来收到的n个只确认一个数据包的ack时，该RTT只用来更新最小RTT,
	 * 因为这些ACK可能是对方delay ack等待后延迟发送的ACK, 不能用来更新RTT最大值。
	 */
	if (tp->sacked_out == 0) {
		if (num_acked == 1 && ca->delack) {
			/* A delayed ACK is only used for the minimum if it is
			 * provenly lower than an existing non-zero minimum.
			 */
			/* delay ack后只能用来更新RTT最小值 */
			ca->rtt.min = min(ca->rtt.min, rtt_us);
			ca->delack--;
			return;
		} else if (num_acked > 1 && ca->delack < 5) {
			ca->delack++; /* 增加delay ack的个数 */
		}
	}

	/* 记录本轮RTT周期中RTT的最小值和最大值 */
	ca->rtt.min = min_not_zero(ca->rtt.min, rtt_us);
	ca->rtt.max = max(ca->rtt.max, rtt_us);
}

static u32 tcp_cdg_ssthresh(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* 保存拥塞窗口以便将来可能的拥塞撤销 */
	ca->undo_cwnd = tp->snd_cwnd;

	/* CDG_BACKOFF状态时乘法因子beta为0.7，可能有两种情况:
	 * 1.梯度退避时会主动进入CWR状态，期间会调用本函数
	 * 2.梯度退避后进入CWR发生了丢包,即在CWR丢包进入RECOVERY时
	 */
	if (ca->state == CDG_BACKOFF)
		return max(2U, (tp->snd_cwnd * min(1024U, backoff_beta)) >> 10);

	/* 如果使用了tolerance策略，
	 * 那么非拥塞丢包(即排队队列没满时)不需要减小窗口
	 */
	if (ca->state == CDG_NONFULL && use_tolerance)
		return tp->snd_cwnd;

	/* 如果使用影子窗口,
	 * 由于影子窗口会在窗口增加时同步回补窗口的增量, 
	 * 所以这里窗口降为shadow_wnd和snd_cwnd窗口一半的大者
	 */
	/* 丢包时shadow_wnd同步降为一半, 同时也限制了shadow_wnd最大为cwnd的两倍 */
	ca->shadow_wnd = min(ca->shadow_wnd >> 1, tp->snd_cwnd); 
	if (use_shadow) 
		return max3(2U, ca->shadow_wnd, tp->snd_cwnd >> 1);

	/* 否则，跟NewReno一样降为一半 */
	return max(2U, tp->snd_cwnd >> 1); 
}

static u32 tcp_cdg_undo_cwnd(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);
	/* 恢复之前的拥塞窗口 */
	return max(tcp_sk(sk)->snd_cwnd, ca->undo_cwnd);
}

static void tcp_cdg_cwnd_event(struct sock *sk, const enum tcp_ca_event ev)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct minmax *gradients;

	switch (ev) {
	case CA_EVENT_CWND_RESTART: /* 应用层空闲之后重启事件
				     * 重置所有变量 
				     */
		gradients = ca->gradients;
		if (gradients)
			memset(gradients, 0, window * sizeof(gradients[0]));
		memset(ca, 0, sizeof(*ca));

		ca->gradients = gradients;
		ca->rtt_seq = tp->snd_nxt;
		ca->shadow_wnd = tp->snd_cwnd;
		break;
	case CA_EVENT_COMPLETE_CWR: /* 退出RECOVERY/CWR事件 */
		ca->state = CDG_UNKNOWN; /* 恢复状态 */
		ca->rtt_seq = tp->snd_nxt; /* 退出CWR时重新设置rtt_seq,说明不会在连续两个RTT内梯度退避 */
		ca->rtt_prev = ca->rtt;
		ca->rtt.v64 = 0;
		break;
	default:
		break;
	}
}

static void tcp_cdg_init(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* We silently fall back to window = 1 if allocation fails. */
	/* 分配window个空间，存放梯度 */
	if (window > 1)
		ca->gradients = kcalloc(window, sizeof(ca->gradients[0]),
					GFP_NOWAIT | __GFP_NOWARN);
	ca->rtt_seq = tp->snd_nxt;
	ca->shadow_wnd = tp->snd_cwnd;
}

static void tcp_cdg_release(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);

	kfree(ca->gradients);
}

struct tcp_congestion_ops tcp_cdg __read_mostly = {
	.cong_avoid = tcp_cdg_cong_avoid,	/* 主要函数, 更新窗口和计算梯度 */
	.cwnd_event = tcp_cdg_cwnd_event,	/* 时间函数，主要重置变量 */
	.pkts_acked = tcp_cdg_acked, 		/* ack确认时调用，用来更新本轮RTT的最小值和最大值 */
	.undo_cwnd = tcp_cdg_undo_cwnd,		/* 拥塞撤销时恢复之前的拥塞窗口 */
	.ssthresh = tcp_cdg_ssthresh,		/* 丢包或者梯度退避时根据乘法因子减小窗口 */
	.release = tcp_cdg_release,
	.init = tcp_cdg_init,
	.owner = THIS_MODULE,
	.name = "cdg",
};

static int __init tcp_cdg_register(void)
{
	if (backoff_beta > 1024 || window < 1 || window > 256)
		return -ERANGE;
	if (!is_power_of_2(window)) /* window的值必须为2的整次幂 */
		return -EINVAL;

	BUILD_BUG_ON(sizeof(struct cdg) > ICSK_CA_PRIV_SIZE);
	tcp_register_congestion_control(&tcp_cdg);
	return 0;
}

static void __exit tcp_cdg_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_cdg);
}

module_init(tcp_cdg_register);
module_exit(tcp_cdg_unregister);
MODULE_AUTHOR("Kenneth Klette Jonassen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP CDG");
