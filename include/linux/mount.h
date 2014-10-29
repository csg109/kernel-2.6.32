/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author:  Marco van Wieringen <mvw@planets.elm.net>
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

/* 以下为vfsmount->mnt_flags的标志 */
#define MNT_NOSUID	0x01
#define MNT_NODEV	0x02
#define MNT_NOEXEC	0x04
#define MNT_NOATIME	0x08
#define MNT_NODIRATIME	0x10
#define MNT_RELATIME	0x20
#define MNT_READONLY	0x40	/* does the user want this to be r/o? */
#define MNT_STRICTATIME 0x80

#define MNT_SHRINKABLE	0x100
#define MNT_WRITE_HOLD	0x200

#define MNT_SHARED	0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE	0x2000	/* if the vfsmount is a unbindable mount */
#define MNT_PNODE_MASK	0x3000	/* propagation flag mask */

/* 每个装载的文件系统对应一个vfsmount结构 */
struct vfsmount {
	struct list_head mnt_hash; 	/* mount_hashtable散列表的链表元素 */
	struct vfsmount *mnt_parent;	/* fs we are mounted on */ /* 装载点所在的父文件系统 */
	struct dentry *mnt_mountpoint;	/* dentry of mountpoint */ /* 装载点在父文件系统中的dentry */
	struct dentry *mnt_root;	/* root of the mounted tree */ /* 当前文件系统的根目录dentry */
	struct super_block *mnt_sb;	/* pointer to superblock */ /* 指向超级块,对每个装载的文件系统有且只有一个超级块 */
	struct list_head mnt_mounts;	/* list of children, anchored here */ /* 子文件系统链表 */
	struct list_head mnt_child;	/* and going through their mnt_child */ /* 链表元素，用于父文件系统中的mnt_mounts链表 */
	int mnt_flags; 			/* 安装标志 */
	__u32 rh_reserved;		/* for use with fanotify */
	struct hlist_head rh_reserved2;	/* for use with fanotify */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */ /* 设备名称 */
	struct list_head mnt_list; 	/* 已安装文件系统描述符的namespace 链表的指针 */
	struct list_head mnt_expire;	/* link in fs-specific expiry list */ /* 用于将所有可能自动过期的装载放置在一个链表上的链表元素 */
	struct list_head mnt_share;	/* circular list of shared mounts */ /* 共享装载链表元素 */
	struct list_head mnt_slave_list;/* list of slave mounts *//* 从属装载链表头 */
	struct list_head mnt_slave;	/* slave list entry */ 	/* 从属装载链表元素 */
	struct vfsmount *mnt_master;	/* slave is on master->mnt_slave_list */ /* 指向主装载 */
	struct mnt_namespace *mnt_ns;	/* containing namespace */ /* 所属的命名空间 */
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	/*
	 * We put mnt_count & mnt_expiry_mark at the end of struct vfsmount
	 * to let these frequently modified fields in a separate cache line
	 * (so that reads of mnt_flags wont ping-pong on SMP machines)
	 */
	atomic_t mnt_count; 		/* 使用计数器 */
	int mnt_expiry_mark;		/* true if marked for expiry */ /* 用来表示装载的文件系统是否已经不再使用 */
	int mnt_pinned;
	int mnt_ghosts;
#ifdef CONFIG_SMP
	int *mnt_writers;
#else
	int mnt_writers;
#endif
};

static inline int *get_mnt_writers_ptr(struct vfsmount *mnt)
{
#ifdef CONFIG_SMP
	return mnt->mnt_writers;
#else
	return &mnt->mnt_writers;
#endif
}

static inline struct vfsmount *mntget(struct vfsmount *mnt)
{
	if (mnt)
		atomic_inc(&mnt->mnt_count);
	return mnt;
}

struct file; /* forward dec */

extern int mnt_want_write(struct vfsmount *mnt);
extern int mnt_want_write_file(struct file *file);
extern int mnt_clone_write(struct vfsmount *mnt);
extern void mnt_drop_write(struct vfsmount *mnt);
extern void mntput_no_expire(struct vfsmount *mnt);
extern void mnt_pin(struct vfsmount *mnt);
extern void mnt_unpin(struct vfsmount *mnt);
extern int __mnt_is_readonly(struct vfsmount *mnt);

static inline void mntput(struct vfsmount *mnt)
{
	if (mnt) {
		mnt->mnt_expiry_mark = 0;
		mntput_no_expire(mnt);
	}
}

extern struct vfsmount *do_kern_mount(const char *fstype, int flags,
				      const char *name, void *data);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

struct nameidata;

struct path;
extern int do_add_mount(struct vfsmount *newmnt, struct path *path,
			int mnt_flags, struct list_head *fslist);

extern void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list);
extern void mark_mounts_for_expiry(struct list_head *mounts);

extern spinlock_t vfsmount_lock;
extern dev_t name_to_dev_t(char *name);

#endif /* _LINUX_MOUNT_H */
