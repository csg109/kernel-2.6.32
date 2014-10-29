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

static int fast_convergence __read_mostly = 1;	/* �������� */
static int beta __read_mostly = 717;		/* 1-�˷���С����, 0.7= 717/1024 */
static int initial_ssthresh __read_mostly;	/* ��������������ֵ��ֻ��hystartδ��������Ч */
static int bic_scale __read_mostly = 41; 	/* �������еĳ���C��ֵΪ0.4 = 41*10/1024 */
static int tcp_friendliness __read_mostly = 1;	/* �Ѻ��ԣ���cubic������reno��ʱʹ��reno������ */
static int hystart __read_mostly = 1; 		/* ����������� */

/* HyStart״̬����
 * 1��packet-train, ��ack-train
 * 2��delay
 * 3��both packet-train and delay
 * Ĭ��2�ַ�����ʹ�ã�����Ϊ3
 */
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16; /* ����cwnd���������ֵ������ʹ��HyStart */
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
				/* ���ڿ���snd_cwnd�����ٶ� */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
				/* ��һ�ζ���ʱ��cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
				/* �ϴζ���ʱ��cwnd */
	u32	last_cwnd;	/* the last snd_cwnd */
				/* ��¼��һ�θ���ʱ��ӵ������ */
	u32	last_time;	/* time when updated last_cwnd */
				/* ��¼��һ�θ���ʱ��ʱ��㣬��last_cwndһ����Ƹ��µ�Ƶ�� */
	u32	bic_origin_point;/* origin point of bic function */
				/* ���µ�Wmax��ȡlast_max_cwnd��snd_cwnd���� */
	u32	bic_K;		/* time to origin point from the beginning of the current epoch */
				/* ����Wmax����Ӧ��ʱ��(���������е�K)��W(bic_K) = Wmax */
	u32	delay_min;	/* min delay (msec << 3) */
				/* ����3λ��(����8��)����СRTT */
	u32	epoch_start;	/* beginning of an epoch */
				/* ��¼������������ʱ�ο�ʼ��ʱ��� */
	u32	ack_cnt;	/* number of acks */
				/* ��¼������������ʱ���ڵ��յ���ack����, ���ڼ���Reno��cwnd */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
				/* ����Reno�㷨����õ�cwnd */
#define ACK_RATIO_SHIFT	4
#define ACK_RATIO_LIMIT (32u << ACK_RATIO_SHIFT)
	u16	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
				/* Ϊ������delay ACK��Ӱ�� */
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
				/* Hystart��delay-increaseʹ�ã� �������ÿ��RTT�ĵڼ���sample */
	u8	found;		/* the exit point is found?  1��yes��0��no */
				/* Hystartʹ�ã� ��ǻ������ʱ�˳����������Ƿ��ҵ�; ����λ�ֱ��Ӧ�ҵ��˳�����㷨HYSTART_ACK_TRAIN����HYSTART_DELAY */
	u32	round_start;	/* beginning of each round */
				/* Hystart��ack-trainʹ�ã����ÿ��RTT��ʼ��ʱ��� */
	u32	end_seq;	/* end_seq of the round */
				/* Hystartʹ�ã�������ʶÿ��RTT�Ľ����� */
	u32	last_ack;	/* last time when the ACK spacing is close */
				/* Hystart��ack-trainʹ�ã����ڼ�¼һ��RTT��ack-train�����ack�յ���ʱ�䣬����2ms����Ϊ�ǲ������� */
	u32	curr_rtt;	/* the minimum rtt of current round */
				/* Hystart��delay-increaseʹ��,��¼ÿ��RTT��sampe����СRTT(����8��) */
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

/* bictcp_hystart_reset�в�û�ж�ca->found��0��
 * Ҳ����˵��ֻ����һ��ʼ���߶���ʱ��HyStart�Ż������ó�������ʱ�䲢��ʹ�á�
 */
static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = bictcp_clock(); /*  ��¼ÿ��RTT��ʼ��ʱ�������ACK��ʱ��� */
	ca->end_seq = tp->snd_nxt; /* ��־��RTT�Ľ����� */
	ca->curr_rtt = 0;	/* ��ʼ������RTT��ȡ��������RTTֵ */
	ca->sample_cnt = 0;	/* ��ʼ������RTT���������� */
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
/* ���������� */
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
/* cubic�ؼ��㷨 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{
	u64 offs;	/*  ʱ��| t - K | */
	u32 delta, t, bic_target, max_cnt; /* delta��cwnd�bic_target��Ԥ��ֵ��tΪԤ��ʱ�� */

	ca->ack_cnt++;	/* count the number of ACKs *//* �������ʱ�����յ�ack�ĸ��� */

	/* 31.25ms���ڲ�����ca */
	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

	/* �����ǰ�������������ʽ����һ��RTT���Ԥ�ڴ��ڴ�С W(t+RTTmin) = C(t+RTTmin - K)^3 + Wmax
	 * ����:
	 * 	CΪcube_rtt_scale 
	 * 	RTTminΪdelay_min>>3��������RTTmin֮��Ĵ��ڴ�С
	 * 	KΪbic_K,��ÿ�ζ�������µĽ׶��м���
	 * 	WmaxΪbic_origin_point
	 */

	/* ������ һ���µ�ʱ�Σ��������K��ֵbic_K�Լ�Wmax��ֵbic_origin_point */
	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_time_stamp;	/* record the beginning of an epoch *//* ��¼ʱ��� */
		ca->ack_cnt = 1;			/* start counting *//* �����յ�ack�ĸ��� */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		/* ȡmax(last_max_cwnd , cwnd)��Ϊ��ǰWmax */
		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else { /* last_max_cwnd > cwnd */
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			/* bic_K������λΪ�룬ת�ɵ�λΪ 1 / 1024�� */
			/* ����bic_K = cubic_root(1/C * (Wmax-cwnd)), ��λΪ1/2024 HZ; cube_factorΪ1/C */
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
	 * Constant = c / srtt = 0.4, ʵ�ʲ���Ϊ0.4 
	 */

	/* change the unit from HZ to bictcp_HZ */
	/* Ԥ��ʱ��Ϊt+RTT����ca->delay_min >> 3�� */
	t = ((tcp_time_stamp + msecs_to_jiffies(ca->delay_min>>3)
	      - ca->epoch_start) << BICTCP_HZ) / HZ;

	/* ����| t - bic_K | */
	if (t < ca->bic_K) /* ��δ�ﵽWmax */		/* t - K */
		offs = ca->bic_K - t;
	else	/* ��ʱ�Ѿ�����Wmax */
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	/* ���� delta = | W(t) - W(bic_K) |  
	 * cube_rtt_scale = (bic_scale * 10) = c / srtt * 2^10��c/srtt = 0.4 
	 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ); /* delta = |C*(t-K)^3| */
	
	/* ����bic_target����Ԥ��W(t+RTT)*/
	if (t < ca->bic_K) /* ��δ�ﵽWmax */ /* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                                	/* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	/* ������W(t+RTT),��W(t+RTT)��cwnd�Աȣ�ȷ��cnt */
	if (bic_target > cwnd) {
		/* ���Խ�࣬����Խ�� */
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		/* Ŀǰcwnd�Ѿ�����Ԥ���ˣ�Ӧ�ý��� */
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	/* һЩ���ػᵼ��HyStart����ǰ�˳����Ӷ����ܳ�����ÿ��ô���
	 * ʵ����HyStart�Ĳ�������ܿ��ܻ�ƫС��
	 * ���Ե��˳�HyStart�󣬽���ӵ������״̬ʱ���������֮ǰû�ж�����������cwnd����������С��5%��
	 * ��ô�Ͱ�cwndÿRTT���������ȵ���Ϊ5%��
	 * ����һ�����ǰ���˳�������ʱ����֤ӵ�����ڵ����ٲ���̫�͡�*/
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

	/* TCP Friendly */
	/*  TCP Friendly �����bic��RENO���� �����cwnd�����ٶȣ�����Сcnt 
	 *  ���ϴζ����Ժ��ʱ��t����ÿ��RTT���� 3B / ( 2 - B)����ô���Եõ� 
	 *  ����RENO�㷨��cwnd�� 
	 *  cwnd (RENO) = cwnd + 3B / (2 - B) * ack_cnt / cwnd 
	 *  BΪ���Լ������ӣ��ڴ��㷨��Ϊ0.3 
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

	/* ����delay ACK��Ӱ��, �����delay ACK, ��cnt���һ��������С��cwnd���� */
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

	/* ���ӵ������С����ֵ���������� */
	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		if (hystart && after(ack, ca->end_seq)) /* һ��RTT�����ˣ���ʼ�µ�һ��RTT */
			bictcp_hystart_reset(sk);
		tcp_slow_start(tp);
	} else { /* ӵ������ */
		bictcp_update(ca, tp->snd_cwnd);
		tcp_cong_avoid_ai(tp, ca->cnt);
	}

}

static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch *//* ������һ��������ʱ�� */

	/* Wmax and fast convergence */
	/* ��������ϴεͣ�˵���񻯣����������� */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		/* last_max_cwnd = 0.85*cwnd */
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else	/* ��������ϴθߣ���˵�����ã���Ȼ���ø���� */
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;

	/* �µ���ֵΪ0.7*snd_cwnd */
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
		bictcp_hystart_reset(sk); /* LOSS״̬���½���������������Ҫ��������Hystart, found������bictcp_reset()������Ϊ0 */
	}
}

/* hystart��������ؼ��㷨 */
static void hystart_update(struct sock *sk, u32 delay)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	if (!(ca->found & hystart_detect)) { /* ����hystart��exit point��û�ҵ� */
		u32 now = bictcp_clock(); /* ���뼶ʱ�� */

		/* first detection parameter - ack-train detection */
		/* ��һ��̽�⣺ack-train */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta) { /* �����ϸ�ACK��2ms�ڲ���������ack-train */
			ca->last_ack = now;
			/* ack-train��˼����:
			 * ack-train��һϵ�е�ack�е�һ��ack�����һ��ackʱ��������ʱ��(1/2����СRTT)������Ϊ��exit point.
			 * ����round_start��Ϊ��RTT�ڵ�һ��ack��ʱ��㣬delay_minΪ����3λ�����СRTT������4λ��1/2��RTTmin
			 */
			if ((s32)(now - ca->round_start) > ca->delay_min >> 4)
				ca->found |= HYSTART_ACK_TRAIN; /* ack-train�ж�Ϊ�������˳��� */
		}

		/* obtain the minimum delay of more than sampling packets */
		/* ����Ϊ�ڶ���̽�⣺delay-increase */
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) { /* ÿ��RTT��ǰ8��ACKΪ����, ��¼��������С��RTTΪ���ε�RTT*/
			if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
				ca->curr_rtt = delay; /* ע�⣬��ʱ��delay��������8�����ֵ */

			ca->sample_cnt++;
		} else { /* ��¼����֮���������RTT(ȡ��RTT��ǰ8������)������СRTT+n(nΪ������ֵ), ����Ϊexit point */
			/* ע�⣺��ʱcurr_rtt��delay_min��������8����ģ���HYSTART_DELAY_THRESH�Ĳ���ʱ�ӵĵ�λΪms
			 * ����ʵ�������Ƶ�Ϊ4-16ms
			 */
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min>>4))
				ca->found |= HYSTART_DELAY; /* delay-increase�ҵ��˳��� */
		}
		/*
		 * Either one of two conditions are met,
		 * we exit from slow start immediately.
		 */
		/* �ҵ����˳��㣬������������ֵ�˳�����������ӵ������ */
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
	u32 delay;	/* �˴ε�RTT  */

	/* �������delayed_ack�������������ack�İ�������ֹһ��,��delayed_ack���
	 * ֮��ñ�����bictcp_update()����������delay ACK��Ӱ��
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
	/* �ڿ��ٻָ���1s�ڲ����в��� */
	if ((s32)(tcp_time_stamp - ca->epoch_start) < HZ)
		return;

	/*  rtt_us��������8���������ʱ�����С8�� */
	delay = (rtt_us << 3) / USEC_PER_MSEC;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	/* ������������󣬴����������׶β���cwnd���ڻ��������С���ڣ����л���������� */
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
	/* beta_scale = 8*(1024 + 717) / 3 / (1024 -717 )����ԼΪ15  */
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
	/* do_div() �������㣬���������x�У����������ڷ���ֵ�С�*/
	/* cube_factor����������bic_K�ģ������е�K��:
	 * bic_K = cubic_root( Wmax*beta)/C ) = cubic_root( Wlast_max - cwnd) / C)
	 * Ϊ�˼���bic_K,������Ҫ�õ�1/C��ֵ������cube_factor=1/C
	 * ��������C��ֵΪ0.4:  C = (bic_scale*10)/(2^10) 
	 * ���ԣ�cube_factor = 1/C = 1/((bic_scale*10)/(2^10)) = (2^10)/(bic_scale*10)
	 *
	 * ���⣬Ϊ����߾��ȣ�ʱ��Ŵ�BICTCP_HZ������2^10�������������bic_K���������ļ��㣬
	 * ��������cube_factor��ʼ��ʱ����2^10�Ļ����϶���3*BICTCP_HZ����
	 * ��1 << (10 + 3*BICTCP_HZ) = 2^10 * 2^(3*BICTCP_HZ)
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
