/*
 * Detect hard and soft lockups on a system
 *
 * started by Don Zickus, Copyright (C) 2010 Red Hat, Inc.
 *
 * this code detects hard lockups: incidents in where on a CPU
 * the kernel does not respond to anything except NMI.
 *
 * Note: Most of this code is borrowed heavily from softlockup.c,
 * so thanks to Ingo for the initial implementation.
 * Some chunks also taken from arch/x86/kernel/apic/nmi.c, thanks
 * to those contributors as well.
 */

#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/lockdep.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/sysctl.h>

#include <asm/irq_regs.h>
#include <linux/perf_event.h>

int watchdog_enabled = 1;
int __read_mostly softlockup_thresh = 60;

static DEFINE_PER_CPU(unsigned long, watchdog_touch_ts); /* 用于softlockup的watchdog时间戳, 在每次watchdog线程被调度时被更新 */
static DEFINE_PER_CPU(struct task_struct *, softlockup_watchdog); /* 用于softlockup的percpu的watchdog线程, 线程函数watchdog() */
static DEFINE_PER_CPU(struct hrtimer, watchdog_hrtimer); /* 用于softlockup的高精度定时器 */
static DEFINE_PER_CPU(bool, softlockup_touch_sync); /* 用于softlockup标记本次检测时更新下时钟 */
static DEFINE_PER_CPU(bool, soft_watchdog_warn); /* 用于softlockup, 用来控制每次软锁时每个CPU只打印一次报警信息 */
#ifdef CONFIG_HARDLOCKUP_DETECTOR
static DEFINE_PER_CPU(bool, hard_watchdog_warn); /* 用于hardlockup控制每次硬锁每个CPU只打印一次报警信息 */
static DEFINE_PER_CPU(bool, watchdog_nmi_touch); /* 用于hardlockup, 标记本次NMI中断不检测hardlockup */
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts); /* 用于hardlockup判断是否硬锁, 在每次高精度定时器触发时自增, NMI中断里检测是否发生变化 */
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts_saved); /* 用于hardlockup在每次NMI中断时记录hrtimer_interrupts值来判断该值有无增加 */
static DEFINE_PER_CPU(struct perf_event *, watchdog_ev); /* 用于hardlockup的perf event, 触发NMI中断 */
#endif

/* boot commands */
/*
 * Should we panic when a soft-lockup or hard-lockup occurs:
 */
#ifdef CONFIG_HARDLOCKUP_DETECTOR
static int hardlockup_panic = 
			CONFIG_BOOTPARAM_HARDLOCKUP_PANIC_VALUE;
static int hardlockup_enable = 
			CONFIG_BOOTPARAM_HARDLOCKUP_ENABLED_VALUE;

/* 这里控制内核启动参数nmi_watchdog= */
static int __init hardlockup_panic_setup(char *str)
{
	/* nmi_watchdog=panic参数, hardlockup时panic */
	if (!strncmp(str, "panic", 5))
		hardlockup_panic = 1;
	/* nmi_watchdog=nopanic参数, hardlockup时只是警告, 不会panic */
	else if (!strncmp(str, "nopanic", 7))
		hardlockup_panic = 0;
	else if (!strncmp(str, "0", 1))
		watchdog_enabled = 0;
	else if (!strncmp(str, "1", 1) ||
		 !strncmp(str, "2", 1))
		hardlockup_enable = 1;
	else if (!strncmp(str, "lapic", 5) ||
		 !strncmp(str, "ioapic", 6))
		hardlockup_enable = 1;
	return 1;
}
__setup("nmi_watchdog=", hardlockup_panic_setup);
#endif

unsigned int __read_mostly softlockup_panic =
			CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC_VALUE;

static int __init softlockup_panic_setup(char *str)
{
	softlockup_panic = simple_strtoul(str, NULL, 0);

	return 1;
}
__setup("softlockup_panic=", softlockup_panic_setup);

static int __init nowatchdog_setup(char *str)
{
	watchdog_enabled = 0;
	return 1;
}
__setup("nowatchdog", nowatchdog_setup);

/* deprecated */
static int __init nosoftlockup_setup(char *str)
{
	watchdog_enabled = 0;
	return 1;
}
__setup("nosoftlockup", nosoftlockup_setup);
/*  */


/*
 * Returns seconds, approximately.  We don't need nanosecond
 * resolution, and we don't need to waste time with a big divide when
 * 2^30ns == 1.074s.
 */
/* 获取CPU时间并转成秒 */
static unsigned long get_timestamp(int this_cpu)
{
	/* 将纳秒转成秒, 右移30位约等于十进制的9位 */
	return cpu_clock(this_cpu) >> 30LL;  /* 2^30 ~= 10^9 */
}

/* 高精度定时器每次触发的时间间隔, 默认12秒 */
static unsigned long get_sample_period(void)
{
	/*
	 * convert softlockup_thresh from seconds to ns
	 * the divide by 5 is to give hrtimer 5 chances to
	 * increment before the hardlockup detector generates
	 * a warning
	 */
	/* 软锁超时为60秒, 这里分成5个时间片检查 */
	return softlockup_thresh / 5 * NSEC_PER_SEC;
}

/* Commands for resetting the watchdog */
static void __touch_watchdog(void)
{
	int this_cpu = smp_processor_id();

	/* 更新时间戳,单位为秒 */
	__get_cpu_var(watchdog_touch_ts) = get_timestamp(this_cpu);
}

/* 用于屏蔽本次softlockup检测
 * 清除watchdog_touch_ts以便屏蔽掉本次softlockup
 */
void touch_softlockup_watchdog(void)
{
	__raw_get_cpu_var(watchdog_touch_ts) = 0;
}
EXPORT_SYMBOL(touch_softlockup_watchdog);

void touch_all_softlockup_watchdogs(void)
{
	int cpu;

	/*
	 * this is done lockless
	 * do we care if a 0 races with a timestamp?
	 * all it means is the softlock check starts one cycle later
	 */
	for_each_online_cpu(cpu)
		per_cpu(watchdog_touch_ts, cpu) = 0;
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
/* 用于手动屏蔽掉watchdog的检测:
 * 在watchdog检测狗咬的时候，看到这个标记，就不再继续监测是否喂过狗了，直接返回
 * 比如硬狗：设置了watchdog_nmi_touch变量；软狗：清除了watchdog_touch_ts计数.
 *
 * 主要用在当内核在处理某些特殊任务的时候，不希望受到这只狗的打扰，
 * 能自我保证当前系统的状态是正常或异常的（也就是处于自知的状态）；
 * 查看它的调用, 如：kdb_bt(kgdb单步调试中)和panic(panic time大于零时的循环等待中)等 
 */
void touch_nmi_watchdog(void)
{
	if (watchdog_enabled) {
		unsigned cpu;

		/* 针对hardlockup设置watchdog_nmi_touch标记,下一次hardlockup就不检测了 */
		for_each_present_cpu(cpu) {
			if (per_cpu(watchdog_nmi_touch, cpu) != true)
				per_cpu(watchdog_nmi_touch, cpu) = true;
		}
	}
	touch_softlockup_watchdog();
}
EXPORT_SYMBOL(touch_nmi_watchdog);

#endif

void touch_softlockup_watchdog_sync(void)
{
	__raw_get_cpu_var(softlockup_touch_sync) = true; /* 需要更新时钟 */
	__raw_get_cpu_var(watchdog_touch_ts) = 0; /* 屏蔽本次softlockup检测 */
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
/* watchdog detector functions */
/* 判断是否发生hard lockup */
static int is_hardlockup(void)
{
	/* 获取高精度watchdog timer的运行次数 */
	unsigned long hrint = __get_cpu_var(hrtimer_interrupts);
	/* 在一个hard lockup检测时间阈值内(NMI触发间隔60秒)，
	 * 如果watchdog timer未运行,说明cpu中断被屏蔽时间超过阈值 
	 * 则认为发生了hardlockup
	 */
	if (__get_cpu_var(hrtimer_interrupts_saved) == hrint)
		return 1;
	/* 记录watchdog timer运行的次数 */
	__get_cpu_var(hrtimer_interrupts_saved) = hrint;
	return 0;
}
#endif

static int is_softlockup(unsigned long touch_ts)
{
	unsigned long now = get_timestamp(smp_processor_id());

	/* Warn about unreasonable delays: */
	/* 检测是否锁住超过softlockup_thresh时间(60秒), 
	 * 超过则返回锁住的时间
	 * touch_ts为上一次更新的时间 
	 */
	if (time_after(now, touch_ts + softlockup_thresh))
		return now - touch_ts;

	return 0; /* 未超时 */
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR

static struct perf_event_attr wd_hw_attr = {
	.type		= PERF_TYPE_HARDWARE,
	.config		= PERF_COUNT_HW_CPU_CYCLES,
	.size		= sizeof(struct perf_event_attr),
	.pinned		= 1,
	.disabled	= 1,
};

/* Callback function for perf event subsystem */
/* hardlockup检测事件发生时的NMI回调函数, 每60秒触发NMI中断时调用
 * 用于判断是否发生了hard lockup并dump hard lockup信息
 */
static void watchdog_overflow_callback(struct perf_event *event, int nmi,
		 struct perf_sample_data *data,
		 struct pt_regs *regs)
{
	/* Ensure the watchdog never gets throttled */
	event->hw.interrupts = 0;

	/* 其他地方调用了touch_nmi_watchdog(调用地方自己确保不发生硬锁), 本次不检测hardlockup */
	if (__get_cpu_var(watchdog_nmi_touch) == true) {
		__get_cpu_var(watchdog_nmi_touch) = false; /* 置位, 下一次还是需要检测的 */
		return;
	}

	/* check for a hardlockup
	 * This is done by making sure our timer interrupt
	 * is incrementing.  The timer interrupt should have
	 * fired multiple times before we overflow'd.  If it hasn't
	 * then this is a good indication the cpu is stuck
	 */
	if (is_hardlockup()) { /* 判断是否发生hardlockup */
		int this_cpu = smp_processor_id();

		/* only print hardlockups once */
		/* hard_watchdog_warn控制每次每个CPU只打印一次警告 */
		if (__get_cpu_var(hard_watchdog_warn) == true)
			return;
		/* 是否直接panic
		 * hardlockup_panic是CONFIG配置的,默认为1, 没有导出到proc参数
		 * 可以通过内核启动参数nmi_watchdog=panic 或 = nopanic控制
		 */
		if (hardlockup_panic) 
			panic("Watchdog detected hard LOCKUP on cpu %d", this_cpu);
		else /* 只是警告 */
			WARN(1, "Watchdog detected hard LOCKUP on cpu %d", this_cpu);

		__get_cpu_var(hard_watchdog_warn) = true;
		return;
	}

	__get_cpu_var(hard_watchdog_warn) = false;
	return;
}

/* 增加定时器触发次数, 用于hardlockup判断是否发生硬锁(NMI中断检测定时器未触发) */
static void watchdog_interrupt_count(void)
{
	__get_cpu_var(hrtimer_interrupts)++;
}
#else
static inline void watchdog_interrupt_count(void) { return; }
#endif /* CONFIG_HARDLOCKUP_DETECTOR */

/* watchdog kicker functions */
/* 高精度定时器处理函数，
 * hardlockup用来喂狗
 * softlockup判断狗咬：唤醒watchdog进程并判断是否发生了软锁 
 */
static enum hrtimer_restart watchdog_timer_fn(struct hrtimer *hrtimer)
{
	/* 获取计数watchdog_touch_ts(单位秒)，该计数在watchdog内核线程被调度时更新 */
	unsigned long touch_ts = __get_cpu_var(watchdog_touch_ts);
	struct pt_regs *regs = get_irq_regs();
	int duration;

	/* kick the hardlockup detector */
	/* 增加定时器触发次数, 用于hardlockup判断是否发生硬锁(NMI中断检测定时器未触发) */
	watchdog_interrupt_count();

	/* kick the softlockup detector */
	/* 唤醒软锁的wathdog内核线程 */
	wake_up_process(__get_cpu_var(softlockup_watchdog));

	/* .. and repeat */
	/* 重启定时器 */
	hrtimer_forward_now(hrtimer, ns_to_ktime(get_sample_period()));

	/* 为0时本次不检测, 因为其他地方调用了touch_softlockup_watchdog暂时屏蔽掉softlockup */
	if (touch_ts == 0) {
		/* 如果设置softlockup_touch_sync则同步更新下时钟 */
		if (unlikely(__get_cpu_var(softlockup_touch_sync))) {
			/*
			 * If the time stamp was touched atomically
			 * make sure the scheduler tick is up to date.
			 */
			__get_cpu_var(softlockup_touch_sync) = false;
			sched_clock_tick(); /* 更新下时钟 */
		}
		__touch_watchdog(); /* 下次还是需要继续检测的 */
		return HRTIMER_RESTART;
	}

	/* check for a softlockup
	 * This is done by making sure a high priority task is
	 * being scheduled.  The task touches the watchdog to
	 * indicate it is getting cpu time.  If it hasn't then
	 * this is a good indication some task is hogging the cpu
	 */
	/* 判断是否发生了软锁，原理是判断touch_ts(时间戳)是否超过一定时间没有更新 */
	duration = is_softlockup(touch_ts);
	if (unlikely(duration)) { /* 软锁超时了 */
		/* only warn once */
		/* soft_watchdog_warn用来控制每个CPU每次软锁只报警一次 */
		if (__get_cpu_var(soft_watchdog_warn) == true)
			return HRTIMER_RESTART;

		/* 发生了软锁后，进行一些列的信息记录和告警 */
		printk(KERN_EMERG "BUG: soft lockup - CPU#%d stuck for %us! [%s:%d]\n",
			smp_processor_id(), duration,
			current->comm, task_pid_nr(current));
		print_modules();
		print_irqtrace_events(current);
		if (regs)
			show_regs(regs);
		else
			dump_stack();

		/* 如果启用了softlockup_panic则直接panic */
		if (softlockup_panic)
			panic("softlockup: hung tasks");
		__get_cpu_var(soft_watchdog_warn) = true;
	} else /* 正常不超时时重置下报警标记 */
		__get_cpu_var(soft_watchdog_warn) = false;

	return HRTIMER_RESTART;
}


/*
 * The watchdog thread - touches the timestamp.
 */
/* watchdog内核线程执行主函数，主要用来更新计数(时间戳) */
static int watchdog(void *unused)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 }; /* 设置为最高优先级 */
	struct hrtimer *hrtimer = &__raw_get_cpu_var(watchdog_hrtimer);

	sched_setscheduler(current, SCHED_FIFO, &param); /* 设置为实时线程 */

	/* initialize timestamp */
	__touch_watchdog(); /* 更新时间戳 */

	/* kick off the timer for the hardlockup detector */
	/* done here because hrtimer_start can only pin to smp_processor_id() */
	/* 启动高精度定时器，用于检测是否发生软锁 */
	hrtimer_start(hrtimer, ns_to_ktime(get_sample_period()),
		      HRTIMER_MODE_REL_PINNED);

	set_current_state(TASK_INTERRUPTIBLE);
	/*
	 * Run briefly once per second to reset the softlockup timestamp.
	 * If this gets delayed for more than 60 seconds then the
	 * debug-printout triggers in watchdog_timer_fn().
	 */
	/* 这里为watchdog线程的主要工作, 即在每次被调度时更新时间戳 */
	while (!kthread_should_stop()) {
		__touch_watchdog(); /* 更新时间戳 */
		schedule(); /* 调度 */

		if (kthread_should_stop())
			break;

		set_current_state(TASK_INTERRUPTIBLE); /* 切换睡眠状态在schedule()后等待定时器里唤醒 */
	}
	__set_current_state(TASK_RUNNING);

	return 0;
}


#ifdef CONFIG_HARDLOCKUP_DETECTOR
/* 开启hard lockup探测
 * 1.初始化hard lockup检测事件
 * 2.hard lockup阈值为60s
 * 2.向performance monitoring子系统注册hard lockup检测事件
 * 3.使能hard lockup检测事件
 * 注：performance monitoring，x86中的硬件设备，当cpu clock经过了指定个周期后发出一个NMI中断。
 */
static int watchdog_nmi_enable(int cpu)
{
	struct perf_event_attr *wd_attr;
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	/*
 	 * People like the simple clean cpu node info
 	 * on boot.  Simplify the noise from the watchdog
 	 * by only printing messages that are different than
 	 * what cpu0 displayed
 	 */
	static unsigned long err0 = 0;

	if (!hardlockup_enable)
		return 0;

	/* is it already setup and enabled? */
	if (event && event->state > PERF_EVENT_STATE_OFF)
		goto out;

	/* it is setup but not enabled */
	if (event != NULL)
		goto out_enable;

	wd_attr = &wd_hw_attr;
	/* hardlockup的NMI触发频率为60秒 */
	wd_attr->sample_period = hw_nmi_get_sample_period();

	/* Try to register using hardware perf events */
	/* 向performance monitoring注册hard lockup检测事件
	 * 60秒的频率触发NMI中断后调用watchdog_overflow_callback检测hardlockup
	 */
	event = perf_event_create_kernel_counter(wd_attr, cpu, NULL, watchdog_overflow_callback, NULL);

	/* save cpu0 error for future comparison */
	if (!cpu)
		err0 = (IS_ERR(event) ? PTR_ERR(event) : 0);

	if (!IS_ERR(event)) {
		/* only print for cpu0 or different than cpu0 */
		if (!cpu || err0)
			printk(KERN_INFO "NMI watchdog enabled, takes one hw-pmu counter.\n");
		goto out_save;
	}

	/* skip displaying the same error again */
	if ((PTR_ERR(event) == err0) && cpu)
		return PTR_ERR(event);

	/* vary the KERN level based on the returned errno */
	if (PTR_ERR(event) == -EOPNOTSUPP)
		printk(KERN_INFO "NMI watchdog disabled (cpu%i): not supported (no LAPIC?)\n", cpu);
	else if (PTR_ERR(event) == -ENOENT)
		printk(KERN_WARNING "NMI watchdog disabled (cpu%i): hardware events not enabled\n", cpu);
	else
		printk(KERN_ERR "NMI watchdog disabled (cpu%i): unable to create perf event: %ld\n", cpu, PTR_ERR(event));
	return PTR_ERR(event);

	/* success path */
out_save:
	per_cpu(watchdog_ev, cpu) = event;
out_enable:
	perf_event_enable(per_cpu(watchdog_ev, cpu)); /* 使能hard lockup的检测 */
out:
	return 0;
}

/* 关闭hard lockup检测机制
 * 1.向performance monitoring子系统注销hard lockup检测控制块
 * 2.清空per-cpu hard lockup检测控制块
 * 3.释放hard lock检测控制块
 */
static void watchdog_nmi_disable(int cpu)
{
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	if (event) {
		/* 向performance monitoring子系统注销hard lockup检测控制块 */
		perf_event_disable(event);
		per_cpu(watchdog_ev, cpu) = NULL;

		/* should be in cleanup, but blocks oprofile */
		/* 释放hard lock检测控制块 */
		perf_event_release_kernel(event);
	}
	return;
}
#else
static int watchdog_nmi_enable(int cpu) { return 0; }
static void watchdog_nmi_disable(int cpu) { return; }
#endif /* CONFIG_HARDLOCKUP_DETECTOR */

/* prepare/enable/disable routines */
static int watchdog_prepare_cpu(int cpu)
{
	/* 获取percpu的高精度定时器 */
	struct hrtimer *hrtimer = &per_cpu(watchdog_hrtimer, cpu);

	WARN_ON(per_cpu(softlockup_watchdog, cpu));
	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL); /* 初始化高精度定时器 */
	hrtimer->function = watchdog_timer_fn; /* 设置定时器处理函数 */

	return 0;
}

/* 这里初始化nmi_watchdog以及用于softlockup的单个CPU的watchdog线程 */
static int watchdog_enable(int cpu)
{
	struct task_struct *p = per_cpu(softlockup_watchdog, cpu);
	int err = 0;

	/* enable the perf event */
	/* 启用nmi_watchdog, 
	 * 通过perf系统来实现NMI中断, 
	 * 相当注册了60秒频率的NMI中断处理函数watchdog_overflow_callback()
	 */
	err = watchdog_nmi_enable(cpu);

	/* Regardless of err above, fall through and start softlockup */

	/* create the watchdog thread */
	if (!p) {
		/* 创建线程, 执行函数为watchdog() */
		p = kthread_create(watchdog, (void *)(unsigned long)cpu, "watchdog/%d", cpu);
		if (IS_ERR(p)) {
			printk(KERN_ERR "softlockup watchdog for %i failed\n", cpu);
			if (!err)
				/* if hardlockup hasn't already set this */
				err = PTR_ERR(p);
			goto out;
		}
		kthread_bind(p, cpu); /* 绑定到cpu */
		per_cpu(watchdog_touch_ts, cpu) = 0; /* 清零时间戳 */
		per_cpu(softlockup_watchdog, cpu) = p; /* 记录percpu线程 */
		wake_up_process(p); /* 唤醒线程 */
	}

out:
	return err;
}

static void watchdog_disable(int cpu)
{
	struct task_struct *p = per_cpu(softlockup_watchdog, cpu);
	struct hrtimer *hrtimer = &per_cpu(watchdog_hrtimer, cpu);

	/*
	 * cancel the timer first to stop incrementing the stats
	 * and waking up the kthread
	 */
	hrtimer_cancel(hrtimer); /* 删除高精度定时器 */

	/* disable the perf event */
	watchdog_nmi_disable(cpu); /* 关闭hardlockup检测 */

	/* stop the watchdog thread */
	/* 关掉watchdog线程 */
	if (p) {
		per_cpu(softlockup_watchdog, cpu) = NULL;
		kthread_stop(p);
	}
}

/* 启用所有CPU的watchdog, 包括softlockup和hardlockup(nmi_watchdog) */
static void watchdog_enable_all_cpus(void)
{
	int cpu;

	watchdog_enabled = 0;

#ifdef CONFIG_HARDLOCKUP_DETECTOR
	/* user is explicitly enabling this */
	hardlockup_enable = 1; /* 启用硬锁检测nmi_watchdog */
#endif
	for_each_online_cpu(cpu)
		if (!watchdog_enable(cpu))
			/* if any cpu succeeds, watchdog is considered
			   enabled for the system */
			/* 只要有一个CPU启动了就算watchdog开启了 */
			watchdog_enabled = 1;

	if (!watchdog_enabled)
		printk(KERN_ERR "watchdog: failed to be enabled on some cpus\n");

}

static void watchdog_disable_all_cpus(void)
{
	int cpu;

	for_each_online_cpu(cpu)
		watchdog_disable(cpu);

	/* if all watchdogs are disabled, then they are disabled for the system */
	watchdog_enabled = 0;
}


/* sysctl functions */
#ifdef CONFIG_SYSCTL
/*
 * proc handler for /proc/sys/kernel/nmi_watchdog
 */
/* 处理watchdog和nmi_watchdog参数(这两个proc参数其实是同一个, 两个只能同时开或者关) */
int proc_dowatchdog_enabled(struct ctl_table *table, int write,
		     void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec(table, write, buffer, length, ppos);

	if (write) {
		/* 如果启用则初始化 */
		if (watchdog_enabled)
			watchdog_enable_all_cpus();
		else /* 关闭 */
			watchdog_disable_all_cpus();
	}
	return 0;
}

int proc_dowatchdog_thresh(struct ctl_table *table, int write,
			     void __user *buffer,
			     size_t *lenp, loff_t *ppos)
{
	return proc_dointvec_minmax(table, write, buffer, lenp, ppos);
}
#endif /* CONFIG_SYSCTL */


/*
 * Create/destroy watchdog threads as CPUs come and go:
 */
static int __cpuinit
cpu_callback(struct notifier_block *nfb, unsigned long action, void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	int err = 0;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		err = watchdog_prepare_cpu(hotcpu); /* 初始化用于softlockup的高精度定时器 */
		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		if (watchdog_enabled)
			err = watchdog_enable(hotcpu); /* 初始化nmi_watchdog以及创建用于softlockup的watchdog线程 */
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		watchdog_disable(hotcpu); /* 停用watchdog*/
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		watchdog_disable(hotcpu);
		break;
#endif /* CONFIG_HOTPLUG_CPU */
	}

	/*
	 * hardlockup and softlockup are not important enough
	 * to block cpu bring up.  Just always succeed and
	 * rely on printk output to flag problems.
	 */
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

/* 因为是在启动的时候调用, 这里只初始化一个CPU, 其余CPU通过注册cpu notifier初始化 */
void __init lockup_detector_init(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err;

	err = cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu); /* 初始化softlockup用的定时器 */
	WARN_ON(notifier_to_errno(err));

	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu); /* 初始化nmi_watchdog和softlockup依赖的watchdog线程 */
	register_cpu_notifier(&cpu_nfb); /* 注册CPU热插拔处理函数 */

	return;
}
