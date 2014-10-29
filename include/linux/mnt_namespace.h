#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/path.h>
#include <linux/seq_file.h>
#include <linux/wait.h>

struct mnt_namespace {
	atomic_t		count; 	/* 使用该命名空间的进程数目 */
	struct vfsmount *	root; 	/* 指向根目录的vfsmount实例 */
	struct list_head	list; 	/* 链表保存了VFS命名空间中所有文件系统的vfsmount实例 */
	wait_queue_head_t poll; 	/* 命名空间等待队列 */
	int event; 			/* 事件 */
};

struct proc_mounts {
	struct seq_file m; /* must be the first element */
	struct mnt_namespace *ns;
	struct path root;
	int event;
};

struct fs_struct;

extern struct mnt_namespace *create_mnt_ns(struct vfsmount *mnt);
extern struct mnt_namespace *copy_mnt_ns(unsigned long, struct mnt_namespace *,
		struct fs_struct *);
extern void put_mnt_ns(struct mnt_namespace *ns);
static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern const struct seq_operations mounts_op;
extern const struct seq_operations mountinfo_op;
extern const struct seq_operations mountstats_op;

#endif
#endif
