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

/* �ݶȵĴ��ڴ�С����paper�е�aֵ
 * ��������Ϊ[1, 256], ����Ϊ2�������� 
 */
static int window __read_mostly = 8; 

/* �˷�����beta, �����ݶ��˱ܵĴ��ڼ�С������Ĭ��Ϊ0.7 */
static unsigned int backoff_beta __read_mostly = 0.7071 * 1024; /* sqrt 0.5 */

/* backoff_factor�൱��paper�е�G������
 * ת����ʽΪ��backoff_factor = 1000/(G * window)
 * ����backoff_factorΪ42�൱��GΪ3
 */
static unsigned int backoff_factor __read_mostly = 42;

/* hystart�Ŀ��أ�����HYSTART_ACK_TRAIN��HYSTART_DELAY */
static unsigned int hystart_detect __read_mostly = 3;

/* ��Ч�ݶ��˱ܵ���ֵ��
 * �������˱���Чuse_ineff�κ�Ͳ���ʹ���ݶ��˱�,
 * ��paper�е�b����
 */
static unsigned int use_ineff __read_mostly = 5;

/* Ӱ�Ӵ��ڿ���
 * ������ģ��NewReno�Ĵ���������
 * Ȼ���ڶ���ʱ��ʹ�ø�ֵ�����ٴ��ڣ��ز�֮ǰ�ݶ��˱���ʧ�Ĵ���
 */
static bool use_shadow __read_mostly = true;

/* tolerance���ԵĿ���, Ĭ���ǹرյġ�
 * �����󣬻��ж�·�ɶ���״̬�Ƿ�����
 * �Դ����ƶ϶����Ƿ�Ϊӵ�����ڣ����Ϊ�����������Ҫ��Сӵ������
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

/* ״̬ */
enum cdg_state {
	CDG_UNKNOWN = 0, /* Ĭ��״̬ */
	CDG_NONFULL = 1, /* �ŶӶ���δ�� */
	CDG_FULL    = 2, /* �ŶӶ����� */
	CDG_BACKOFF = 3, /* �ݶ��˱�״̬ */
};

/* cdg��Ҫ�ṹ�壬�Ѿ�������icsk��64�ֽ� */
struct cdg {
	struct minmax rtt;		/* ����RTT���ڵ�RTT */
	struct minmax rtt_prev; 	/* ��¼��һ��RTT���ڵ�RTT */
	struct minmax *gradients;	/* gradients���������window��RTTֵ��
					   ��¼��window�ڵ�����g(n),����g(max,n)��g(min,n) */
	struct minmax gsum;		/* gsum�ۼ������� g(n) - g(n-window), ֱ�ӱ�ʾ�ݶ�G(n) */
	bool gfilled;			/* ������Ǹտ�ʼ�ɼ�ʱ��gradients�����Ƿ��Ѿ�����window�� */
	u8  tail;			/* gradients��������� */
	u8  state;	/* ״̬, ��cdg_state���� */
	u8  delack;	/* ��¼delay ack�ĸ��� */
	u32 rtt_seq; 	/* ��¼snd_nxt, �����жϱ��һ��RTT���� */
	u32 undo_cwnd;	/* ����ӵ������,���涪��ʱ��ӵ������ */
	u32 shadow_wnd; /* Ӱ�Ӵ���, ����ģ��NewReno���ڵ�����, �ڶ���ʱʹ�ø�ֵ���ز�֮ǰ�����ݶ��˱���ʧ�Ĵ��� */
	u16 backoff_cnt;/* ��¼�����ݶ��˱ܵĴ���������˱ܴ�������use_ineff,����Ϊ�˱���Ч�����˱� */
	u16 sample_cnt;	/* Hystart��delay-increaseʹ��, �������ÿ��RTT�ĵڼ���sample */
	s32 delay_min;	/* Hystartʹ�ã���¼��СRTT */
	u32 last_ack; 	/* Hystart��ack-trainʹ�ã����ڼ�¼һ��RTT��ack-train�����ack�յ���ʱ�䣬����3ms����Ϊ�ǲ������� */
	u32 round_start;/* Hystart��ack-trainʹ�ã����ÿ��RTT���ڿ�ʼ��ʱ��� */
};

/**
 * nexp_u32 - negative base-e exponential
 * @ux: x in units of micro
 *
 * Returns exp(ux * -1e-6) * U32_MAX.
 */
static u32 __pure nexp_u32(u32 ux)
{
	/* v����Ϊ e(-x) * 65536 -1 �ľ���ֵ��e(-x)Ϊe��-x����,
	 * ����xΪ0, 0.000256, 0.000512, 0.001024 ... 
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

	/* �ɼ���СRTT */
	ca->delay_min = min_not_zero(ca->delay_min, ca->rtt.min);
	if (ca->delay_min == 0)
		return;

	/* ack-train̽��, ack-train��˼����:
	 * ack-train��һϵ�е�ack�е�һ��ack�����һ��ackʱ�������ڵ���ʱ��(1/2����СRTT)������Ϊ��exit point.
	 */
	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now_us = div_u64(local_clock(), NSEC_PER_USEC); /* ��ǰʱ�̣�����תΪ΢�� */

		if (ca->last_ack == 0 || !tcp_is_cwnd_limited(sk)) { /* ÿ��RTT���ڿ�ʼ����Ӧ�ò�����ʱ����ʼ�µ�̽������ */
			ca->last_ack = now_us;
			ca->round_start = now_us;
		} else if (before(now_us, ca->last_ack + 3000)) { /* �����ϸ�ACK��3ms�ڲ���������ack-train */
			u32 base_owd = max(ca->delay_min / 2U, 125U); /* ����ʱ�ӣ���1/2 minRTT, ������СֵΪ125΢�� */

			ca->last_ack = now_us; /* �������ACKʱ�� */

	 		/* ����round_startΪ��RTT�ڵ�һ��ack��ʱ��㣬
			 * ����������˵����Ҫ�˳�������
			 */
			if (after(now_us, ca->round_start + base_owd)) {
				NET_INC_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTTRAINDETECT);
				NET_ADD_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTTRAINCWND,
						 tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd; /* ����ӵ������ */
				return;
			}
		}
	}

	/* delay-increase, ����˼���ǣ�
	 * �������RTT���ڲɼ���RTT����(ȡǰ8����������Сֵ)����������СRTT(delay_min) + n(nΪ������ֵ), ����Ϊexit point
	 */
	if (hystart_detect & HYSTART_DELAY) {
		if (ca->sample_cnt < 8) { /* ÿ��RTT��ǰ8��ACKΪ����, ��¼��������С��RTTΪ���ε�RTT, 
					   *��¼��ca->rtt.min��¼, �������ﲻ�ټ�¼
					   */
			ca->sample_cnt++;
		} else {
			/* ������ֵnΪ 1+1/8 delay_min, ������СֵΪ125΢�� */
			s32 thresh = max(ca->delay_min + ca->delay_min / 8U,
					 125U);

			/* RTTsimple > max(1+1/8 RTTmin, 125US) , �����������˳�������*/
			if (ca->rtt.min > thresh) {
				NET_INC_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTDELAYDETECT);
				NET_ADD_STATS_BH(sock_net(sk),
						 LINUX_MIB_TCPHYSTARTDELAYCWND,
						 tp->snd_cwnd);
				tp->snd_ssthresh = tp->snd_cwnd; /* ����ӵ������ */
			}
		}
	}
}

static s32 tcp_cdg_grad(struct cdg *ca)
{
	s32 gmin = ca->rtt.min - ca->rtt_prev.min; /* ���㱾��RTTmin������g(min,n) */
	s32 gmax = ca->rtt.max - ca->rtt_prev.max; /* ���㱾��RTTmax������g(max,n) */
	s32 grad; /* �ݶ�G(n) */

	/* �����ƶ�ƽ����G(n)ʱ��paper�ṩ������ʽ(4)�����ݶ�G(n):
	 * 	G(n) = G(n-1) + ( g(n) - g(n-window) ) / window
	 *
	 * ���ǣ�ʵ����paper�в��죬���ǲ�û�г���windowֵ������Ϊ��
	 * 	G(n) = G(n-1) + ( g(n) - g(n-window) )
	 *
	 * ���µ�gsum��ΪG(n)
	 */
	if (ca->gradients) {
		/* gsum�ۼ������� g(n) - g(n-window) */
		ca->gsum.min += gmin - ca->gradients[ca->tail].min;
		ca->gsum.max += gmax - ca->gradients[ca->tail].max;
		/* gradient�����¼��window�ڵ�����g(n),����g(max,n)��g(min,n) */
		ca->gradients[ca->tail].min = gmin;
		ca->gradients[ca->tail].max = gmax;
		/* gradient������������ */
		ca->tail = (ca->tail + 1) & (window - 1);
		/* ����ȡ��gsum��ֵ */
		gmin = ca->gsum.min;
		gmax = ca->gsum.max;
	}

	/* We keep sums to ignore gradients during cwnd reductions;
	 * the paper's smoothed gradients otherwise simplify to:
	 * (rtt_latest - rtt_oldest) / window.
	 *
	 * We also drop division by window here.
	 */
	/* �ݶ�grad���gmin����0,��ȡgmin������ȡgmax */
	grad = gmin > 0 ? gmin : gmax;

	/* Extrapolate missing values in gradient window: */
	/* ����տ�ʼ�ɼ�ʱwindow�ڵ����ݻ�δ������� */
	if (!ca->gfilled) { 
		if (!ca->gradients && window > 1)
			grad *= window; /* Memory allocation failed. */
		else if (ca->tail == 0)
			/* window�������������ɼ���window��RTT�������� */
			ca->gfilled = true; 
		else
			/* ���տ�ʼ�ɼ�������û����windowʱ, G(n)��Ҫ���㴦�� */
			grad = (grad * window) / (int)ca->tail;
	}

	/* Backoff was effectual: */
	/* �ݶ��˱�֮��,G(min,n)����G(max,n)Ϊ������˵���˱�����Ч���ģ�
	 * ��ô�����Ч�˱ܼ���
	 */
	if (gmin <= -32 || gmax <= -32)
		ca->backoff_cnt = 0;

	/* ���ʹ����tolerance, ����жϵ�ǰ���ŶӶ��е�״̬(����������δ��)
	 * �ڶ���ʱ�Ϳ��������ж��Ƿ�Ϊӵ������, �����ӵ�������Ͳ��ü�Сӵ������
	 */
	if (use_tolerance) {
		/* Reduce small variations to zero: */
		/* ����64��Ϊ�����Ӿ��� */
		gmin = DIV_ROUND_CLOSEST(gmin, 64);
		gmax = DIV_ROUND_CLOSEST(gmax, 64);

		/* RTTmax�Ѿ��������󣬶�RTTmin���ڳ�������˵���ŶӶ�������, ״̬�л�ΪFULL */
		if (gmin > 0 && gmax <= 0)
			ca->state = CDG_FULL;
		/* ������������˵�����з�����״̬�л�ΪNOFULL:
		 * 1.RTTmin��RTTmax���ڳ�������˵�������е����ݰ�Խ��Խ�󣬵��ǻ�û��
		 * 2. RTTmax�Ѿ������ؼ�С��˵�����д�����״̬��ʼ��Ϊδ����״̬
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

	/* �����ݶ�ֵgrad�����ݶ��˱ܸ��ʣ�
	 * Ȼ�������ֵ���бȽ��������Ƿ�����ݶ��˱�
	 *
	 * paper���˱ܸ���P�ļ��㹫ʽΪ��
	 * 	P[backoff] = 1 - e^(-(G(n)/G))
	 * 	����G(n)���ݶ�ֵgrad, ����G��ת��Ϊbackoff_factor,ת����ʽΪ backoff_factor = 1000/(G * window) 
	 *
	 * nexp_u32()������ʹ�ʽ����[0, 1]�ĸ���ֵת��32λֵ���ڸ�prandom_u32()���ص����ֵ�Ƚ�
	 */
	if (prandom_u32() <= nexp_u32(grad * backoff_factor))
		return false;

	/* ����paper�е�ineffectual backoff detection
	 * ԭ���ǵ��ݶ��˱�use_ineff�κ�gmin��gmax���ǷǸ�, 
	 * ��˵�������˱ܵ���Ч�ģ���Ϊ�����ڸ����ڶ�����ӵ���㷨������
	 * �������ǲ���ʹ���ݶ��˱�
	 */
	if (use_ineff) {
		ca->backoff_cnt++;
		if (ca->backoff_cnt > use_ineff)
			return false;
	}

	ca->shadow_wnd = max(ca->shadow_wnd, tp->snd_cwnd); /* �˱�ʱ��¼Ӱ�Ӵ��� */
	ca->state = CDG_BACKOFF; /* �����˱�״̬�����˳�CWR״̬ʱ������ΪCDG_UNKNOWN */

	/* �ݶ��˱�ֱ�ӽ���CWR״̬�� 
	 * tcp_enter_cwr()�����tcp_cdg_ssthresh()ʹ�ó˷����Ӽ�С
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

	/* ������ʱʹ��hystart����Ƿ���Ҫ�˳������� */
	if (tcp_in_slow_start(tp) && hystart_detect)
		tcp_cdg_hystart_update(sk);

	/* ÿ��RTT����ʹ���ݶ�������Ƿ�ӵ�� */
	if (after(ack, ca->rtt_seq) && ca->rtt.v64) {
		s32 grad = 0;	/* ���ڱ��������ݶ� */

		if (ca->rtt_prev.v64) 		/* �ڶ���RTT���ڲſ�ʼ�����ݶ� */
			grad = tcp_cdg_grad(ca);/* �����ݶ��㷨�õ��ݶ�ֵ */
		ca->rtt_seq = tp->snd_nxt; 	/* ��¼��һ��RTT���� */
		ca->rtt_prev = ca->rtt; 	/* ����ǰһ��RTT���ڵ�RTT */
		ca->rtt.v64 = 0; 		/* ����RTT���� */
		ca->last_ack = 0; 		/* hystart�����ACKʱ������ */
		ca->sample_cnt = 0; 		/* hystart������������ */

		/* �������õ����ݶ�ֵ����0��˵��������Ҫӵ���˱ܡ�
		 * tcp_cdg_backoff()�л�����˱ܸ��ʣ�����ʱ�����˱�
		 */
		if (grad > 0 && tcp_cdg_backoff(sk, grad))
			return;
	}

	/* �����Ǹ�paper������
	 * ��Ӧ�ò�����ʱ������Ӱ�Ӵ���Ϊ������ӵ������
	 */
	if (!tcp_is_cwnd_limited(sk)) {
		ca->shadow_wnd = min(ca->shadow_wnd, tp->snd_cwnd);
		return;
	}

	prior_snd_cwnd = tp->snd_cwnd;
	tcp_reno_cong_avoid(sk, ack, acked); /* ����reno�ӿ�����ӵ������ */

	/* Ӱ�Ӵ��ڻ�ͬ���ز����ڵ������������paper�е�lost transmission opportunities */
	incr = tp->snd_cwnd - prior_snd_cwnd; /* ӵ���������� */
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
	/* �����ų�delay ack��RTT��Ӱ�죺
	 * ��û��SACKʱ,
	 * ����delay ack(һ��ȷ�ϳ���һ����)ʱ����¼delay ack�ĸ���n(n<5),
	 * Ȼ���ڽ������յ���n��ֻȷ��һ�����ݰ���ackʱ����RTTֻ����������СRTT,
	 * ��Ϊ��ЩACK�����ǶԷ�delay ack�ȴ����ӳٷ��͵�ACK, ������������RTT���ֵ��
	 */
	if (tp->sacked_out == 0) {
		if (num_acked == 1 && ca->delack) {
			/* A delayed ACK is only used for the minimum if it is
			 * provenly lower than an existing non-zero minimum.
			 */
			/* delay ack��ֻ����������RTT��Сֵ */
			ca->rtt.min = min(ca->rtt.min, rtt_us);
			ca->delack--;
			return;
		} else if (num_acked > 1 && ca->delack < 5) {
			ca->delack++; /* ����delay ack�ĸ��� */
		}
	}

	/* ��¼����RTT������RTT����Сֵ�����ֵ */
	ca->rtt.min = min_not_zero(ca->rtt.min, rtt_us);
	ca->rtt.max = max(ca->rtt.max, rtt_us);
}

static u32 tcp_cdg_ssthresh(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* ����ӵ�������Ա㽫�����ܵ�ӵ������ */
	ca->undo_cwnd = tp->snd_cwnd;

	/* CDG_BACKOFF״̬ʱ�˷�����betaΪ0.7���������������:
	 * 1.�ݶ��˱�ʱ����������CWR״̬���ڼ����ñ�����
	 * 2.�ݶ��˱ܺ����CWR�����˶���,����CWR��������RECOVERYʱ
	 */
	if (ca->state == CDG_BACKOFF)
		return max(2U, (tp->snd_cwnd * min(1024U, backoff_beta)) >> 10);

	/* ���ʹ����tolerance���ԣ�
	 * ��ô��ӵ������(���ŶӶ���û��ʱ)����Ҫ��С����
	 */
	if (ca->state == CDG_NONFULL && use_tolerance)
		return tp->snd_cwnd;

	/* ���ʹ��Ӱ�Ӵ���,
	 * ����Ӱ�Ӵ��ڻ��ڴ�������ʱͬ���ز����ڵ�����, 
	 * �������ﴰ�ڽ�Ϊshadow_wnd��snd_cwnd����һ��Ĵ���
	 */
	/* ����ʱshadow_wndͬ����Ϊһ��, ͬʱҲ������shadow_wnd���Ϊcwnd������ */
	ca->shadow_wnd = min(ca->shadow_wnd >> 1, tp->snd_cwnd); 
	if (use_shadow) 
		return max3(2U, ca->shadow_wnd, tp->snd_cwnd >> 1);

	/* ���򣬸�NewRenoһ����Ϊһ�� */
	return max(2U, tp->snd_cwnd >> 1); 
}

static u32 tcp_cdg_undo_cwnd(struct sock *sk)
{
	struct cdg *ca = inet_csk_ca(sk);
	/* �ָ�֮ǰ��ӵ������ */
	return max(tcp_sk(sk)->snd_cwnd, ca->undo_cwnd);
}

static void tcp_cdg_cwnd_event(struct sock *sk, const enum tcp_ca_event ev)
{
	struct cdg *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct minmax *gradients;

	switch (ev) {
	case CA_EVENT_CWND_RESTART: /* Ӧ�ò����֮�������¼�
				     * �������б��� 
				     */
		gradients = ca->gradients;
		if (gradients)
			memset(gradients, 0, window * sizeof(gradients[0]));
		memset(ca, 0, sizeof(*ca));

		ca->gradients = gradients;
		ca->rtt_seq = tp->snd_nxt;
		ca->shadow_wnd = tp->snd_cwnd;
		break;
	case CA_EVENT_COMPLETE_CWR: /* �˳�RECOVERY/CWR�¼� */
		ca->state = CDG_UNKNOWN; /* �ָ�״̬ */
		ca->rtt_seq = tp->snd_nxt; /* �˳�CWRʱ��������rtt_seq,˵����������������RTT���ݶ��˱� */
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
	/* ����window���ռ䣬����ݶ� */
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
	.cong_avoid = tcp_cdg_cong_avoid,	/* ��Ҫ����, ���´��ںͼ����ݶ� */
	.cwnd_event = tcp_cdg_cwnd_event,	/* ʱ�亯������Ҫ���ñ��� */
	.pkts_acked = tcp_cdg_acked, 		/* ackȷ��ʱ���ã��������±���RTT����Сֵ�����ֵ */
	.undo_cwnd = tcp_cdg_undo_cwnd,		/* ӵ������ʱ�ָ�֮ǰ��ӵ������ */
	.ssthresh = tcp_cdg_ssthresh,		/* ���������ݶ��˱�ʱ���ݳ˷����Ӽ�С���� */
	.release = tcp_cdg_release,
	.init = tcp_cdg_init,
	.owner = THIS_MODULE,
	.name = "cdg",
};

static int __init tcp_cdg_register(void)
{
	if (backoff_beta > 1024 || window < 1 || window > 256)
		return -ERANGE;
	if (!is_power_of_2(window)) /* window��ֵ����Ϊ2�������� */
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
