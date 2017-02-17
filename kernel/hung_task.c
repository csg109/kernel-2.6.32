/*
 * Detect Hung Task
 *
 * kernel/hung_task.c - kernel thread for detecting tasks stuck in D state
 *
 */

#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/sysctl.h>

/*
 * The number of tasks checked:
 */
unsigned long __read_mostly sysctl_hung_task_check_count = PID_MAX_LIMIT;

/*
 * Limit number of tasks checked in a batch.
 *
 * This value controls the preemptibility of khungtaskd since preemption
 * is disabled during the critical section. It also controls the size of
 * the RCU grace period. So it needs to be upper-bound.
 */
#define HUNG_TASK_BATCHING 1024

/*
 * Zero means infinite timeout - no checking done:
 */
unsigned long __read_mostly sysctl_hung_task_timeout_secs = 120;

unsigned long __read_mostly sysctl_hung_task_warnings = 10;

static int __read_mostly did_panic;

static struct task_struct *watchdog_task;

/*
 * Should we panic (and reboot, if panic_timeout= is set) when a
 * hung task is detected:
 */
unsigned int __read_mostly sysctl_hung_task_panic =
				CONFIG_BOOTPARAM_HUNG_TASK_PANIC_VALUE;

static int __init hung_task_panic_setup(char *str)
{
	sysctl_hung_task_panic = simple_strtoul(str, NULL, 0);

	return 1;
}
__setup("hung_task_panic=", hung_task_panic_setup);

static int
hung_task_panic(struct notifier_block *this, unsigned long event, void *ptr)
{
	did_panic = 1;

	return NOTIFY_DONE;
}

static struct notifier_block panic_block = {
	.notifier_call = hung_task_panic,
};

static void check_hung_task(struct task_struct *t, unsigned long timeout)
{
	/* �����������л��������Դ����жϸý����Ƿ��������� */
	unsigned long switch_count = t->nvcsw + t->nivcsw;

	/*
	 * Ensure the task is not frozen.
	 * Also, when a freshly created task is scheduled once, changes
	 * its state to TASK_UNINTERRUPTIBLE without having ever been
	 * switched out once, it musn't be checked.
	 */
	if (unlikely(t->flags & PF_FROZEN || !switch_count))
		return;

	/* �����ǰswitch_count����last_switch_count��
	 * ��˵����khungtaskd���̱������ڼ䣬�ý���û�з��������ȡ�
	 * Ҳ����˵���ý���һֱ����D״̬����Ϊlast_switch_countֻ���������.
	 * hung task�����е�120s��ʵ��ͨ��khungtaskd�ں��̵߳Ļ������������Ƶģ�
	 * ����ͨ��per task����������
	 */
	if (switch_count != t->last_switch_count) {
		/* ����last_switch_count������ֻ��������£��ü���ר����hung task�ļ�� */
		t->last_switch_count = switch_count;
		return;
	}
	/* hung task�����ӡ�������ƣ�Ĭ��Ϊ10�Σ�
	 * ��ϵͳ�����ڼ�����ӡ10�Σ�������Ͳ���ӡ��
	 * ��Ҫ��ӡҪ�ٴ�����sysctl_hung_task_warnings
	 */
	if (!sysctl_hung_task_warnings)
		return;
	sysctl_hung_task_warnings--;

	/*
	 * Ok, the task did not get scheduled for more than 2 minutes,
	 * complain:
	 */
	/* ����Ϳ�ʼ��ӡhung task������Ϣ�� */
	printk(KERN_ERR "INFO: task %s:%d blocked for more than "
			"%ld seconds.\n", t->comm, t->pid, timeout);
	printk(KERN_ERR "\"echo 0 > /proc/sys/kernel/hung_task_timeout_secs\""
			" disables this message.\n");
	sched_show_task(t); /* ��ӡ��ջ */
	__debug_show_held_locks(t); /* ���������debug_lock�����ӡ����ռ����� */

	touch_nmi_watchdog(); /* touch nmi_watchdog��صļ���������ֹ�ڴ˹����д���nmi_watchdog */

	/* ���������hung_task_panic�򴥷�panic */
	if (sysctl_hung_task_panic)
		panic("hung_task: blocked tasks");
}

/*
 * To avoid extending the RCU grace period for an unbounded amount of time,
 * periodically exit the critical section and enter a new one.
 *
 * For preemptible RCU it is sufficient to call rcu_read_unlock in order
 * exit the grace period. For classic RCU, a reschedule is required.
 */
static void rcu_lock_break(struct task_struct *g, struct task_struct *t)
{
	get_task_struct(g);
	get_task_struct(t);
	rcu_read_unlock();
	cond_resched();
	rcu_read_lock();
	put_task_struct(t);
	put_task_struct(g);
}

/*
 * Check whether a TASK_UNINTERRUPTIBLE does not get woken up for
 * a really long time (120 seconds). If that happens, print out
 * a warning.
 */
/* ����ϵͳ�е����н��̣�����Ƿ��д���D״̬����120s�Ľ��̣���������ӡ�澯��panic */
static void check_hung_uninterruptible_tasks(unsigned long timeout)
{
	/* hung task��������������Ĭ��Ϊ���Ľ��̺�(64bitĬ����4M������) */
	int max_count = sysctl_hung_task_check_count;
	/* ÿ�α��������������ޣ�Ĭ��Ϊ1024����������Ŀ����Ϊ��:
	 * 1����ֹrcu_read_lock��ռ��ʱ��̫����
	 * 2��hung task��watchdogռ��CPUʱ��̫�������û���ں���ռ��������ں��̲߳��������ȵĻ����ǲ��ܷ��������л���
	 */
	int batch_count = HUNG_TASK_BATCHING;
	struct task_struct *g, *t;

	/*
	 * If the system crashed already then all bets are off,
	 * do not report extra hung tasks:
	 */
	/* ���ϵͳ�Ѿ�����crash״̬�ˣ��Ͳ��ڱ�hung task�� */
	if (test_taint(TAINT_DIE) || did_panic)
		return;

	rcu_read_lock();
	do_each_thread(g, t) { /* ����ϵͳ�е����н��� */
		if (!--max_count) /* ���н��̱������˳� */
			goto unlock;
		/* ���ÿ�μ��Ľ�����������1024�ˣ�����Ҫ������ȣ�����rcu�������� */
		if (!--batch_count) {
			batch_count = HUNG_TASK_BATCHING;
			/* �ͷ�rcu������������ */
			rcu_lock_break(g, t);
			/* Exit if t or g was unhashed during refresh. */
			/* ���Ȼ���������Ӧ�����Ƿ��ڣ���������ˣ����˳�������������� */
			if (t->state == TASK_DEAD || g->state == TASK_DEAD)
				goto unlock;
		}
		/* use "==" to skip the TASK_KILLABLE tasks waiting on NFS */
		if (t->state == TASK_UNINTERRUPTIBLE) /* ������״̬�Ƿ�ΪD */
			check_hung_task(t, timeout); /* �����̴���D״̬��ʱ���Ƿ񳬹�timeout(120s) */
	} while_each_thread(g, t); /* ����ͬһ���̵������߳� */
 unlock:
	rcu_read_unlock();
}

static unsigned long timeout_jiffies(unsigned long timeout)
{
	/* timeout of 0 will disable the watchdog */
	return timeout ? timeout * HZ : MAX_SCHEDULE_TIMEOUT;
}

/*
 * Process updating of timeout sysctl
 */
int proc_dohung_task_timeout_secs(struct ctl_table *table, int write,
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos)
{
	int ret;

	ret = proc_doulongvec_minmax(table, write, buffer, lenp, ppos);

	if (ret || !write)
		goto out;

	wake_up_process(watchdog_task);

 out:
	return ret;
}

/*
 * kthread which checks for tasks stuck in D state
 */
static int watchdog(void *dummy)
{
	/* ���õ�ǰkhungtaskd�ں��̵߳�niceΪ0������ͨ���ȼ���Ϊ�˲�Ӱ��ҵ������ */
	set_user_nice(current, 0);

	for ( ; ; ) {
		/* ���̴���D״̬��ʱ������, Ĭ��120s */
		unsigned long timeout = sysctl_hung_task_timeout_secs;

		/* ����߳�(watchdog)sleep 120s(Ĭ��)���ٴλ��� */
		while (schedule_timeout_interruptible(timeout_jiffies(timeout)))
			timeout = sysctl_hung_task_timeout_secs;

		/* ������ִ��ʵ�ʵļ����� */
		check_hung_uninterruptible_tasks(timeout);
	}

	return 0;
}

static int __init hung_task_init(void)
{
	/* ע��panic֪ͨ������panicʱִ����ز��� */
	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);
	/* �����ں��߳�khungtaskd��ִ�к���Ϊwatchdog */
	watchdog_task = kthread_run(watchdog, NULL, "khungtaskd");

	return 0;
}

module_init(hung_task_init);
