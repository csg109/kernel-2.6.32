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
	/* 进程上下文切换计数，以此来判断该进程是否发生过调度 */
	unsigned long switch_count = t->nvcsw + t->nivcsw;

	/*
	 * Ensure the task is not frozen.
	 * Also, when a freshly created task is scheduled once, changes
	 * its state to TASK_UNINTERRUPTIBLE without having ever been
	 * switched out once, it musn't be checked.
	 */
	if (unlikely(t->flags & PF_FROZEN || !switch_count))
		return;

	/* 如果当前switch_count等于last_switch_count，
	 * 则说明在khungtaskd进程被唤醒期间，该进程没有发生过调度。
	 * 也就是说，该进程一直处于D状态，因为last_switch_count只在这里更新.
	 * hung task机制中的120s其实是通过khungtaskd内核线程的唤醒周期来控制的，
	 * 不是通过per task其它计数。
	 */
	if (switch_count != t->last_switch_count) {
		/* 更新last_switch_count计数，只在这里更新，该计数专用于hung task的检测 */
		t->last_switch_count = switch_count;
		return;
	}
	/* hung task错误打印次数限制，默认为10次，
	 * 即系统运行期间最多打印10次，超过后就不打印了
	 * 需要打印要再次设置sysctl_hung_task_warnings
	 */
	if (!sysctl_hung_task_warnings)
		return;
	sysctl_hung_task_warnings--;

	/*
	 * Ok, the task did not get scheduled for more than 2 minutes,
	 * complain:
	 */
	/* 这里就开始打印hung task报警信息了 */
	printk(KERN_ERR "INFO: task %s:%d blocked for more than "
			"%ld seconds.\n", t->comm, t->pid, timeout);
	printk(KERN_ERR "\"echo 0 > /proc/sys/kernel/hung_task_timeout_secs\""
			" disables this message.\n");
	sched_show_task(t); /* 打印堆栈 */
	__debug_show_held_locks(t); /* 如果开启了debug_lock，则打印锁的占用情况 */

	touch_nmi_watchdog(); /* touch nmi_watchdog相关的计数器，防止在此过程中触发nmi_watchdog */

	/* 如果设置了hung_task_panic则触发panic */
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
/* 遍历系统中的所有进程，检测是否有处于D状态超过120s的进程，如果有则打印告警或panic */
static void check_hung_uninterruptible_tasks(unsigned long timeout)
{
	/* hung task检查的最大进程数，默认为最大的进程号(64bit默认是4M个进程) */
	int max_count = sysctl_hung_task_check_count;
	/* 每次遍历进程数的上限，默认为1024，这样做的目的是为了:
	 * 1、防止rcu_read_lock的占用时间太长。
	 * 2、hung task的watchdog占用CPU时间太长。如果没开内核抢占，则如果内核线程不主动调度的话，是不能发生进程切换的
	 */
	int batch_count = HUNG_TASK_BATCHING;
	struct task_struct *g, *t;

	/*
	 * If the system crashed already then all bets are off,
	 * do not report extra hung tasks:
	 */
	/* 如果系统已经处于crash状态了，就不在报hung task了 */
	if (test_taint(TAINT_DIE) || did_panic)
		return;

	rcu_read_lock();
	do_each_thread(g, t) { /* 遍历系统中的所有进程 */
		if (!--max_count) /* 所有进程遍历完退出 */
			goto unlock;
		/* 如果每次检测的进程数量超过1024了，则需要发起调度，结束rcu优雅周期 */
		if (!--batch_count) {
			batch_count = HUNG_TASK_BATCHING;
			/* 释放rcu，并主动调度 */
			rcu_lock_break(g, t);
			/* Exit if t or g was unhashed during refresh. */
			/* 调度回来后检查相应进程是否还在，如果不在了，则退出遍历，否则继续 */
			if (t->state == TASK_DEAD || g->state == TASK_DEAD)
				goto unlock;
		}
		/* use "==" to skip the TASK_KILLABLE tasks waiting on NFS */
		if (t->state == TASK_UNINTERRUPTIBLE) /* 检测进程状态是否为D */
			check_hung_task(t, timeout); /* 检测进程处于D状态的时间是否超过timeout(120s) */
	} while_each_thread(g, t); /* 遍历同一进程的所有线程 */
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
	/* 设置当前khungtaskd内核线程的nice为0，即普通优先级，为了不影响业务运行 */
	set_user_nice(current, 0);

	for ( ; ; ) {
		/* 进程处于D状态的时间上限, 默认120s */
		unsigned long timeout = sysctl_hung_task_timeout_secs;

		/* 检测线程(watchdog)sleep 120s(默认)后，再次唤醒 */
		while (schedule_timeout_interruptible(timeout_jiffies(timeout)))
			timeout = sysctl_hung_task_timeout_secs;

		/* 醒来后执行实际的检测操作 */
		check_hung_uninterruptible_tasks(timeout);
	}

	return 0;
}

static int __init hung_task_init(void)
{
	/* 注册panic通知链，在panic时执行相关操作 */
	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);
	/* 创建内核线程khungtaskd，执行函数为watchdog */
	watchdog_task = kthread_run(watchdog, NULL, "khungtaskd");

	return 0;
}

module_init(hung_task_init);
