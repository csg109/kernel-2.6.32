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

static DEFINE_PER_CPU(unsigned long, watchdog_touch_ts); /* ����softlockup��watchdogʱ���, ��ÿ��watchdog�̱߳�����ʱ������ */
static DEFINE_PER_CPU(struct task_struct *, softlockup_watchdog); /* ����softlockup��percpu��watchdog�߳�, �̺߳���watchdog() */
static DEFINE_PER_CPU(struct hrtimer, watchdog_hrtimer); /* ����softlockup�ĸ߾��ȶ�ʱ�� */
static DEFINE_PER_CPU(bool, softlockup_touch_sync); /* ����softlockup��Ǳ��μ��ʱ������ʱ�� */
static DEFINE_PER_CPU(bool, soft_watchdog_warn); /* ����softlockup, ��������ÿ������ʱÿ��CPUֻ��ӡһ�α�����Ϣ */
#ifdef CONFIG_HARDLOCKUP_DETECTOR
static DEFINE_PER_CPU(bool, hard_watchdog_warn); /* ����hardlockup����ÿ��Ӳ��ÿ��CPUֻ��ӡһ�α�����Ϣ */
static DEFINE_PER_CPU(bool, watchdog_nmi_touch); /* ����hardlockup, ��Ǳ���NMI�жϲ����hardlockup */
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts); /* ����hardlockup�ж��Ƿ�Ӳ��, ��ÿ�θ߾��ȶ�ʱ������ʱ����, NMI�ж������Ƿ����仯 */
static DEFINE_PER_CPU(unsigned long, hrtimer_interrupts_saved); /* ����hardlockup��ÿ��NMI�ж�ʱ��¼hrtimer_interruptsֵ���жϸ�ֵ�������� */
static DEFINE_PER_CPU(struct perf_event *, watchdog_ev); /* ����hardlockup��perf event, ����NMI�ж� */
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

/* ��������ں���������nmi_watchdog= */
static int __init hardlockup_panic_setup(char *str)
{
	/* nmi_watchdog=panic����, hardlockupʱpanic */
	if (!strncmp(str, "panic", 5))
		hardlockup_panic = 1;
	/* nmi_watchdog=nopanic����, hardlockupʱֻ�Ǿ���, ����panic */
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
/* ��ȡCPUʱ�䲢ת���� */
static unsigned long get_timestamp(int this_cpu)
{
	/* ������ת����, ����30λԼ����ʮ���Ƶ�9λ */
	return cpu_clock(this_cpu) >> 30LL;  /* 2^30 ~= 10^9 */
}

/* �߾��ȶ�ʱ��ÿ�δ�����ʱ����, Ĭ��12�� */
static unsigned long get_sample_period(void)
{
	/*
	 * convert softlockup_thresh from seconds to ns
	 * the divide by 5 is to give hrtimer 5 chances to
	 * increment before the hardlockup detector generates
	 * a warning
	 */
	/* ������ʱΪ60��, ����ֳ�5��ʱ��Ƭ��� */
	return softlockup_thresh / 5 * NSEC_PER_SEC;
}

/* Commands for resetting the watchdog */
static void __touch_watchdog(void)
{
	int this_cpu = smp_processor_id();

	/* ����ʱ���,��λΪ�� */
	__get_cpu_var(watchdog_touch_ts) = get_timestamp(this_cpu);
}

/* �������α���softlockup���
 * ���watchdog_touch_ts�Ա����ε�����softlockup
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
/* �����ֶ����ε�watchdog�ļ��:
 * ��watchdog��⹷ҧ��ʱ�򣬿��������ǣ��Ͳ��ټ�������Ƿ�ι�����ˣ�ֱ�ӷ���
 * ����Ӳ����������watchdog_nmi_touch���������������watchdog_touch_ts����.
 *
 * ��Ҫ���ڵ��ں��ڴ���ĳЩ���������ʱ�򣬲�ϣ���ܵ���ֻ���Ĵ��ţ�
 * �����ұ�֤��ǰϵͳ��״̬���������쳣�ģ�Ҳ���Ǵ�����֪��״̬����
 * �鿴���ĵ���, �磺kdb_bt(kgdb����������)��panic(panic time������ʱ��ѭ���ȴ���)�� 
 */
void touch_nmi_watchdog(void)
{
	if (watchdog_enabled) {
		unsigned cpu;

		/* ���hardlockup����watchdog_nmi_touch���,��һ��hardlockup�Ͳ������ */
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
	__raw_get_cpu_var(softlockup_touch_sync) = true; /* ��Ҫ����ʱ�� */
	__raw_get_cpu_var(watchdog_touch_ts) = 0; /* ���α���softlockup��� */
}

#ifdef CONFIG_HARDLOCKUP_DETECTOR
/* watchdog detector functions */
/* �ж��Ƿ���hard lockup */
static int is_hardlockup(void)
{
	/* ��ȡ�߾���watchdog timer�����д��� */
	unsigned long hrint = __get_cpu_var(hrtimer_interrupts);
	/* ��һ��hard lockup���ʱ����ֵ��(NMI�������60��)��
	 * ���watchdog timerδ����,˵��cpu�жϱ�����ʱ�䳬����ֵ 
	 * ����Ϊ������hardlockup
	 */
	if (__get_cpu_var(hrtimer_interrupts_saved) == hrint)
		return 1;
	/* ��¼watchdog timer���еĴ��� */
	__get_cpu_var(hrtimer_interrupts_saved) = hrint;
	return 0;
}
#endif

static int is_softlockup(unsigned long touch_ts)
{
	unsigned long now = get_timestamp(smp_processor_id());

	/* Warn about unreasonable delays: */
	/* ����Ƿ���ס����softlockup_threshʱ��(60��), 
	 * �����򷵻���ס��ʱ��
	 * touch_tsΪ��һ�θ��µ�ʱ�� 
	 */
	if (time_after(now, touch_ts + softlockup_thresh))
		return now - touch_ts;

	return 0; /* δ��ʱ */
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
/* hardlockup����¼�����ʱ��NMI�ص�����, ÿ60�봥��NMI�ж�ʱ����
 * �����ж��Ƿ�����hard lockup��dump hard lockup��Ϣ
 */
static void watchdog_overflow_callback(struct perf_event *event, int nmi,
		 struct perf_sample_data *data,
		 struct pt_regs *regs)
{
	/* Ensure the watchdog never gets throttled */
	event->hw.interrupts = 0;

	/* �����ط�������touch_nmi_watchdog(���õط��Լ�ȷ��������Ӳ��), ���β����hardlockup */
	if (__get_cpu_var(watchdog_nmi_touch) == true) {
		__get_cpu_var(watchdog_nmi_touch) = false; /* ��λ, ��һ�λ�����Ҫ���� */
		return;
	}

	/* check for a hardlockup
	 * This is done by making sure our timer interrupt
	 * is incrementing.  The timer interrupt should have
	 * fired multiple times before we overflow'd.  If it hasn't
	 * then this is a good indication the cpu is stuck
	 */
	if (is_hardlockup()) { /* �ж��Ƿ���hardlockup */
		int this_cpu = smp_processor_id();

		/* only print hardlockups once */
		/* hard_watchdog_warn����ÿ��ÿ��CPUֻ��ӡһ�ξ��� */
		if (__get_cpu_var(hard_watchdog_warn) == true)
			return;
		/* �Ƿ�ֱ��panic
		 * hardlockup_panic��CONFIG���õ�,Ĭ��Ϊ1, û�е�����proc����
		 * ����ͨ���ں���������nmi_watchdog=panic �� = nopanic����
		 */
		if (hardlockup_panic) 
			panic("Watchdog detected hard LOCKUP on cpu %d", this_cpu);
		else /* ֻ�Ǿ��� */
			WARN(1, "Watchdog detected hard LOCKUP on cpu %d", this_cpu);

		__get_cpu_var(hard_watchdog_warn) = true;
		return;
	}

	__get_cpu_var(hard_watchdog_warn) = false;
	return;
}

/* ���Ӷ�ʱ����������, ����hardlockup�ж��Ƿ���Ӳ��(NMI�жϼ�ⶨʱ��δ����) */
static void watchdog_interrupt_count(void)
{
	__get_cpu_var(hrtimer_interrupts)++;
}
#else
static inline void watchdog_interrupt_count(void) { return; }
#endif /* CONFIG_HARDLOCKUP_DETECTOR */

/* watchdog kicker functions */
/* �߾��ȶ�ʱ����������
 * hardlockup����ι��
 * softlockup�жϹ�ҧ������watchdog���̲��ж��Ƿ��������� 
 */
static enum hrtimer_restart watchdog_timer_fn(struct hrtimer *hrtimer)
{
	/* ��ȡ����watchdog_touch_ts(��λ��)���ü�����watchdog�ں��̱߳�����ʱ���� */
	unsigned long touch_ts = __get_cpu_var(watchdog_touch_ts);
	struct pt_regs *regs = get_irq_regs();
	int duration;

	/* kick the hardlockup detector */
	/* ���Ӷ�ʱ����������, ����hardlockup�ж��Ƿ���Ӳ��(NMI�жϼ�ⶨʱ��δ����) */
	watchdog_interrupt_count();

	/* kick the softlockup detector */
	/* ����������wathdog�ں��߳� */
	wake_up_process(__get_cpu_var(softlockup_watchdog));

	/* .. and repeat */
	/* ������ʱ�� */
	hrtimer_forward_now(hrtimer, ns_to_ktime(get_sample_period()));

	/* Ϊ0ʱ���β����, ��Ϊ�����ط�������touch_softlockup_watchdog��ʱ���ε�softlockup */
	if (touch_ts == 0) {
		/* �������softlockup_touch_sync��ͬ��������ʱ�� */
		if (unlikely(__get_cpu_var(softlockup_touch_sync))) {
			/*
			 * If the time stamp was touched atomically
			 * make sure the scheduler tick is up to date.
			 */
			__get_cpu_var(softlockup_touch_sync) = false;
			sched_clock_tick(); /* ������ʱ�� */
		}
		__touch_watchdog(); /* �´λ�����Ҫ�������� */
		return HRTIMER_RESTART;
	}

	/* check for a softlockup
	 * This is done by making sure a high priority task is
	 * being scheduled.  The task touches the watchdog to
	 * indicate it is getting cpu time.  If it hasn't then
	 * this is a good indication some task is hogging the cpu
	 */
	/* �ж��Ƿ�����������ԭ�����ж�touch_ts(ʱ���)�Ƿ񳬹�һ��ʱ��û�и��� */
	duration = is_softlockup(touch_ts);
	if (unlikely(duration)) { /* ������ʱ�� */
		/* only warn once */
		/* soft_watchdog_warn��������ÿ��CPUÿ������ֻ����һ�� */
		if (__get_cpu_var(soft_watchdog_warn) == true)
			return HRTIMER_RESTART;

		/* �����������󣬽���һЩ�е���Ϣ��¼�͸澯 */
		printk(KERN_EMERG "BUG: soft lockup - CPU#%d stuck for %us! [%s:%d]\n",
			smp_processor_id(), duration,
			current->comm, task_pid_nr(current));
		print_modules();
		print_irqtrace_events(current);
		if (regs)
			show_regs(regs);
		else
			dump_stack();

		/* ���������softlockup_panic��ֱ��panic */
		if (softlockup_panic)
			panic("softlockup: hung tasks");
		__get_cpu_var(soft_watchdog_warn) = true;
	} else /* ��������ʱʱ�����±������ */
		__get_cpu_var(soft_watchdog_warn) = false;

	return HRTIMER_RESTART;
}


/*
 * The watchdog thread - touches the timestamp.
 */
/* watchdog�ں��߳�ִ������������Ҫ�������¼���(ʱ���) */
static int watchdog(void *unused)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO-1 }; /* ����Ϊ������ȼ� */
	struct hrtimer *hrtimer = &__raw_get_cpu_var(watchdog_hrtimer);

	sched_setscheduler(current, SCHED_FIFO, &param); /* ����Ϊʵʱ�߳� */

	/* initialize timestamp */
	__touch_watchdog(); /* ����ʱ��� */

	/* kick off the timer for the hardlockup detector */
	/* done here because hrtimer_start can only pin to smp_processor_id() */
	/* �����߾��ȶ�ʱ�������ڼ���Ƿ������� */
	hrtimer_start(hrtimer, ns_to_ktime(get_sample_period()),
		      HRTIMER_MODE_REL_PINNED);

	set_current_state(TASK_INTERRUPTIBLE);
	/*
	 * Run briefly once per second to reset the softlockup timestamp.
	 * If this gets delayed for more than 60 seconds then the
	 * debug-printout triggers in watchdog_timer_fn().
	 */
	/* ����Ϊwatchdog�̵߳���Ҫ����, ����ÿ�α�����ʱ����ʱ��� */
	while (!kthread_should_stop()) {
		__touch_watchdog(); /* ����ʱ��� */
		schedule(); /* ���� */

		if (kthread_should_stop())
			break;

		set_current_state(TASK_INTERRUPTIBLE); /* �л�˯��״̬��schedule()��ȴ���ʱ���﻽�� */
	}
	__set_current_state(TASK_RUNNING);

	return 0;
}


#ifdef CONFIG_HARDLOCKUP_DETECTOR
/* ����hard lockup̽��
 * 1.��ʼ��hard lockup����¼�
 * 2.hard lockup��ֵΪ60s
 * 2.��performance monitoring��ϵͳע��hard lockup����¼�
 * 3.ʹ��hard lockup����¼�
 * ע��performance monitoring��x86�е�Ӳ���豸����cpu clock������ָ�������ں󷢳�һ��NMI�жϡ�
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
	/* hardlockup��NMI����Ƶ��Ϊ60�� */
	wd_attr->sample_period = hw_nmi_get_sample_period();

	/* Try to register using hardware perf events */
	/* ��performance monitoringע��hard lockup����¼�
	 * 60���Ƶ�ʴ���NMI�жϺ����watchdog_overflow_callback���hardlockup
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
	perf_event_enable(per_cpu(watchdog_ev, cpu)); /* ʹ��hard lockup�ļ�� */
out:
	return 0;
}

/* �ر�hard lockup������
 * 1.��performance monitoring��ϵͳע��hard lockup�����ƿ�
 * 2.���per-cpu hard lockup�����ƿ�
 * 3.�ͷ�hard lock�����ƿ�
 */
static void watchdog_nmi_disable(int cpu)
{
	struct perf_event *event = per_cpu(watchdog_ev, cpu);

	if (event) {
		/* ��performance monitoring��ϵͳע��hard lockup�����ƿ� */
		perf_event_disable(event);
		per_cpu(watchdog_ev, cpu) = NULL;

		/* should be in cleanup, but blocks oprofile */
		/* �ͷ�hard lock�����ƿ� */
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
	/* ��ȡpercpu�ĸ߾��ȶ�ʱ�� */
	struct hrtimer *hrtimer = &per_cpu(watchdog_hrtimer, cpu);

	WARN_ON(per_cpu(softlockup_watchdog, cpu));
	hrtimer_init(hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL); /* ��ʼ���߾��ȶ�ʱ�� */
	hrtimer->function = watchdog_timer_fn; /* ���ö�ʱ�������� */

	return 0;
}

/* �����ʼ��nmi_watchdog�Լ�����softlockup�ĵ���CPU��watchdog�߳� */
static int watchdog_enable(int cpu)
{
	struct task_struct *p = per_cpu(softlockup_watchdog, cpu);
	int err = 0;

	/* enable the perf event */
	/* ����nmi_watchdog, 
	 * ͨ��perfϵͳ��ʵ��NMI�ж�, 
	 * �൱ע����60��Ƶ�ʵ�NMI�жϴ�����watchdog_overflow_callback()
	 */
	err = watchdog_nmi_enable(cpu);

	/* Regardless of err above, fall through and start softlockup */

	/* create the watchdog thread */
	if (!p) {
		/* �����߳�, ִ�к���Ϊwatchdog() */
		p = kthread_create(watchdog, (void *)(unsigned long)cpu, "watchdog/%d", cpu);
		if (IS_ERR(p)) {
			printk(KERN_ERR "softlockup watchdog for %i failed\n", cpu);
			if (!err)
				/* if hardlockup hasn't already set this */
				err = PTR_ERR(p);
			goto out;
		}
		kthread_bind(p, cpu); /* �󶨵�cpu */
		per_cpu(watchdog_touch_ts, cpu) = 0; /* ����ʱ��� */
		per_cpu(softlockup_watchdog, cpu) = p; /* ��¼percpu�߳� */
		wake_up_process(p); /* �����߳� */
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
	hrtimer_cancel(hrtimer); /* ɾ���߾��ȶ�ʱ�� */

	/* disable the perf event */
	watchdog_nmi_disable(cpu); /* �ر�hardlockup��� */

	/* stop the watchdog thread */
	/* �ص�watchdog�߳� */
	if (p) {
		per_cpu(softlockup_watchdog, cpu) = NULL;
		kthread_stop(p);
	}
}

/* ��������CPU��watchdog, ����softlockup��hardlockup(nmi_watchdog) */
static void watchdog_enable_all_cpus(void)
{
	int cpu;

	watchdog_enabled = 0;

#ifdef CONFIG_HARDLOCKUP_DETECTOR
	/* user is explicitly enabling this */
	hardlockup_enable = 1; /* ����Ӳ�����nmi_watchdog */
#endif
	for_each_online_cpu(cpu)
		if (!watchdog_enable(cpu))
			/* if any cpu succeeds, watchdog is considered
			   enabled for the system */
			/* ֻҪ��һ��CPU�����˾���watchdog������ */
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
/* ����watchdog��nmi_watchdog����(������proc������ʵ��ͬһ��, ����ֻ��ͬʱ�����߹�) */
int proc_dowatchdog_enabled(struct ctl_table *table, int write,
		     void __user *buffer, size_t *length, loff_t *ppos)
{
	proc_dointvec(table, write, buffer, length, ppos);

	if (write) {
		/* ����������ʼ�� */
		if (watchdog_enabled)
			watchdog_enable_all_cpus();
		else /* �ر� */
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
		err = watchdog_prepare_cpu(hotcpu); /* ��ʼ������softlockup�ĸ߾��ȶ�ʱ�� */
		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		if (watchdog_enabled)
			err = watchdog_enable(hotcpu); /* ��ʼ��nmi_watchdog�Լ���������softlockup��watchdog�߳� */
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		watchdog_disable(hotcpu); /* ͣ��watchdog*/
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

/* ��Ϊ����������ʱ�����, ����ֻ��ʼ��һ��CPU, ����CPUͨ��ע��cpu notifier��ʼ�� */
void __init lockup_detector_init(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err;

	err = cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu); /* ��ʼ��softlockup�õĶ�ʱ�� */
	WARN_ON(notifier_to_errno(err));

	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu); /* ��ʼ��nmi_watchdog��softlockup������watchdog�߳� */
	register_cpu_notifier(&cpu_nfb); /* ע��CPU�Ȳ�δ����� */

	return;
}
