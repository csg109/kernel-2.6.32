/*
 * linux/include/linux/jbd.h
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>
 *
 * Copyright 1998-2000 Red Hat, Inc --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Definitions for transaction data structures for the buffer cache
 * filesystem journaling support.
 */

#ifndef _LINUX_JBD_H
#define _LINUX_JBD_H

/* Allow this file to be included directly into e2fsprogs */
#ifndef __KERNEL__
#include "jfs_compat.h"
#define JFS_DEBUG
#define jfs_debug jbd_debug
#else

#include <linux/types.h>
#include <linux/buffer_head.h>
#include <linux/journal-head.h>
#include <linux/stddef.h>
#include <linux/bit_spinlock.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/lockdep.h>

#define journal_oom_retry 1

/*
 * Define JBD_PARANOID_IOFAIL to cause a kernel BUG() if ext3 finds
 * certain classes of error which can occur due to failed IOs.  Under
 * normal use we want ext3 to continue after such errors, because
 * hardware _can_ fail, but for debugging purposes when running tests on
 * known-good hardware we may want to trap these errors.
 */
#undef JBD_PARANOID_IOFAIL

/*
 * The default maximum commit age, in seconds.
 */
#define JBD_DEFAULT_MAX_COMMIT_AGE 5

#ifdef CONFIG_JBD_DEBUG
/*
 * Define JBD_EXPENSIVE_CHECKING to enable more expensive internal
 * consistency checks.  By default we don't do this unless
 * CONFIG_JBD_DEBUG is on.
 */
#define JBD_EXPENSIVE_CHECKING
extern u8 journal_enable_debug;

#define jbd_debug(n, f, a...)						\
	do {								\
		if ((n) <= journal_enable_debug) {			\
			printk (KERN_DEBUG "(%s, %d): %s: ",		\
				__FILE__, __LINE__, __func__);	\
			printk (f, ## a);				\
		}							\
	} while (0)
#else
#define jbd_debug(f, a...)	/**/
#endif

static inline void *jbd_alloc(size_t size, gfp_t flags)
{
	return (void *)__get_free_pages(flags, get_order(size));
}

static inline void jbd_free(void *ptr, size_t size)
{
	free_pages((unsigned long)ptr, get_order(size));
};

#define JFS_MIN_JOURNAL_BLOCKS 1024


/**
 * typedef handle_t - The handle_t type represents a single atomic update being performed by some process.
 *
 * All filesystem modifications made by the process go
 * through this handle.  Recursive operations (such as quota operations)
 * are gathered into a single update.
 *
 * The buffer credits field is used to account for journaled buffers
 * being modified by the running process.  To ensure that there is
 * enough log space for all outstanding operations, we need to limit the
 * number of outstanding buffers possible at any time.  When the
 * operation completes, any buffer credits not used are credited back to
 * the transaction, so that at all times we know how many buffers the
 * outstanding updates on a transaction might possibly touch.
 *
 * This is an opaque datatype.
 **/
typedef struct handle_s		handle_t;	/* Atomic operation type */


/**
 * typedef journal_t - The journal_t maintains all of the journaling state information for a single filesystem.
 *
 * journal_t is linked to from the fs superblock structure.
 *
 * We use the journal_t to keep track of all outstanding transaction
 * activity on the filesystem, and to manage the state of the log
 * writing process.
 *
 * This is an opaque datatype.
 **/
typedef struct journal_s	journal_t;	/* Journal control structure */
#endif

/*
 * Internal structures used by the logging mechanism:
 */

#define JFS_MAGIC_NUMBER 0xc03b3998U /* The first 4 bytes of /dev/random! */

/*
 * On-disk structures
 */

/*
 * Descriptor block types:
 */

#define JFS_DESCRIPTOR_BLOCK	1 	/* 描述符块 */
#define JFS_COMMIT_BLOCK	2 	/* 提交块 */
#define JFS_SUPERBLOCK_V1	3 	/* 超级块V1版本 */
#define JFS_SUPERBLOCK_V2	4 	/* 超级块V2版本，现在都使用V2 */
#define JFS_REVOKE_BLOCK	5 	/* 取消块 */

/*
 * Standard header for all descriptor blocks:
 */
typedef struct journal_header_s
{
	__be32		h_magic;	/* h_magic是一个幻数，
					 * 如果是一个日志块的描述块，则为JFS_MAGIC_NUMBER，
					 * 否则该块就不是一个日志描述块。
					 */
	__be32		h_blocktype; 	/* 该块的类型，即上面五种块之一 */
	__be32		h_sequence; 	/* 本描述块对应的transaction的序号 */
} journal_header_t;


/*
 * The block tag: used to describe a single buffer in the journal
 */
/* 在描述符块中, 使用journal_block_tag_t结构来描述日志中的一个块与磁盘上的一个块的对应关系的。*/
typedef struct journal_block_tag_s
{
	__be32		t_blocknr;	/* The on-disk block number */ 
					/* 表示日志中的本块对应磁盘原始位置的块号 */
	__be32		t_flags;	/* See below *//* 见下面四个标志 */
} journal_block_tag_t;

/*
 * The revoke descriptor: used on disk to describe a series of blocks to
 * be revoked from the log
 */
typedef struct journal_revoke_header_s
{
	journal_header_t r_header;
	__be32		 r_count;	/* Count of bytes used in the block *//* 记录取消块尾部的偏移 */
} journal_revoke_header_t; 		/* 要写入磁盘中日志的取消块的描述头 */


/* Definitions for the journal tag flags word: */
#define JFS_FLAG_ESCAPE		1	/* on-disk block is escaped */ /* 表示该块的数据被转义了 */
#define JFS_FLAG_SAME_UUID	2	/* block has same uuid as previous */ /* 表示与前一项具有相同的UUID */
#define JFS_FLAG_DELETED	4	/* block deleted by this transaction */ /* 在jbd中没有使用 */
#define JFS_FLAG_LAST_TAG	8	/* last tag in this descriptor block */ /* 表示是最后一项 */


/*
 * The journal superblock.  All fields are in big-endian byte order.
 */
typedef struct journal_superblock_s
{
/* 0x0000 */
	journal_header_t s_header; 	/* 用于表示本块是一个超级块 */

/* 0x000C */
	/* Static information describing the journal */
	__be32	s_blocksize;		/* journal device blocksize */ 
					/* journal所在设备的块大小 */
	__be32	s_maxlen;		/* total blocks in journal file */
					/* 日志的长度，即包含多少个块 */
	__be32	s_first;		/* first block of log information */
					/* 日志中的开始块号，
					 * 注意日志相当于一个文件，
					 * 这里提到的开始块号是文件中的逻辑块号，
					 * 而不是磁盘的物理块号。
					 * 初始化时置为1，因为超级块本身占用了逻辑块0。
					 * 注意s_maxlen和s_first是在格式化时确定的，
					 * 以后就不会改变了。
					 */

/* 0x0018 */
	/* Dynamic information describing the current state of the log */
	__be32	s_sequence;		/* first commit ID expected in log */
					/* 日志中第一个期待的commit ID
					   就是指该值应该是日志中最旧的一个事务的ID 
					  */
	__be32	s_start;		/* blocknr of start of log */
					/* 日志开始的块号
					 * s_start为0 表示不需要恢复
					 * 因为日志空间需要重复使用，相当于一个环形结构，
					 * s_start表示本次有效日志块的起点
					 *
					 * s_start在更新超级块时从journal_s->j_tail赋值而来
					 */

/* 0x0020 */
	/* Error value, as set by journal_abort(). */
	__be32	s_errno; 		/* jbd 出错标志 */

/* 0x0024 */
	/* 注意：下列各域只有在superblock v2 中才有效 */
	/* Remaining fields are only valid in a version-2 superblock */
	__be32	s_feature_compat;	/* compatible feature set */ /* 兼容特性的位图 */
	__be32	s_feature_incompat;	/* incompatible feature set */ /* 不兼容特性的位图 */
	__be32	s_feature_ro_compat;	/* readonly-compatible feature set */ /* 不兼容特性的位图 */
/* 0x0030 */
	__u8	s_uuid[16];		/* 128-bit uuid for journal */ /* UUID，复制自文件系统的UUID */

/* 0x0040 */
	__be32	s_nr_users;		/* Nr of filesystems sharing log */ /* 共享使用本日志的用户数 */

	__be32	s_dynsuper;		/* Blocknr of dynamic superblock copy*/

/* 0x0048 */
	__be32	s_max_transaction;	/* Limit of journal blocks per trans.*/
	__be32	s_max_trans_data;	/* Limit of data blocks per trans. */

/* 0x0050 */
	__u32	s_padding[44];

/* 0x0100 */
	__u8	s_users[16*48];		/* ids of all fs'es sharing the log */
/* 0x0400 */
} journal_superblock_t;

#define JFS_HAS_COMPAT_FEATURE(j,mask)					\
	((j)->j_format_version >= 2 &&					\
	 ((j)->j_superblock->s_feature_compat & cpu_to_be32((mask))))
#define JFS_HAS_RO_COMPAT_FEATURE(j,mask)				\
	((j)->j_format_version >= 2 &&					\
	 ((j)->j_superblock->s_feature_ro_compat & cpu_to_be32((mask))))
#define JFS_HAS_INCOMPAT_FEATURE(j,mask)				\
	((j)->j_format_version >= 2 &&					\
	 ((j)->j_superblock->s_feature_incompat & cpu_to_be32((mask))))

#define JFS_FEATURE_INCOMPAT_REVOKE	0x00000001

/* Features known to this kernel version: */
#define JFS_KNOWN_COMPAT_FEATURES	0
#define JFS_KNOWN_ROCOMPAT_FEATURES	0
#define JFS_KNOWN_INCOMPAT_FEATURES	JFS_FEATURE_INCOMPAT_REVOKE

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/sched.h>

#define J_ASSERT(assert)	BUG_ON(!(assert))

#if defined(CONFIG_BUFFER_DEBUG)
void buffer_assertion_failure(struct buffer_head *bh);
#define J_ASSERT_BH(bh, expr)						\
	do {								\
		if (!(expr))						\
			buffer_assertion_failure(bh);			\
		J_ASSERT(expr);						\
	} while (0)
#define J_ASSERT_JH(jh, expr)	J_ASSERT_BH(jh2bh(jh), expr)
#else
#define J_ASSERT_BH(bh, expr)	J_ASSERT(expr)
#define J_ASSERT_JH(jh, expr)	J_ASSERT(expr)
#endif

#if defined(JBD_PARANOID_IOFAIL)
#define J_EXPECT(expr, why...)		J_ASSERT(expr)
#define J_EXPECT_BH(bh, expr, why...)	J_ASSERT_BH(bh, expr)
#define J_EXPECT_JH(jh, expr, why...)	J_ASSERT_JH(jh, expr)
#else
#define __journal_expect(expr, why...)					     \
	({								     \
		int val = (expr);					     \
		if (!val) {						     \
			printk(KERN_ERR					     \
				"EXT3-fs unexpected failure: %s;\n",# expr); \
			printk(KERN_ERR why "\n");			     \
		}							     \
		val;							     \
	})
#define J_EXPECT(expr, why...)		__journal_expect(expr, ## why)
#define J_EXPECT_BH(bh, expr, why...)	__journal_expect(expr, ## why)
#define J_EXPECT_JH(jh, expr, why...)	__journal_expect(expr, ## why)
#endif

enum jbd_state_bits {
	BH_JBD			/* Has an attached ext3 journal_head */
	  = BH_PrivateStart,
	BH_JWrite,		/* Being written to log (@@@ DEBUGGING) */
	BH_Freed,		/* Has been freed (truncated) */
	BH_Revoked,		/* Has been revoked from the log */
	BH_RevokeValid,		/* Revoked flag is valid */
	BH_JBDDirty,		/* Is dirty but journaled */
	BH_State,		/* Pins most journal_head state */
	BH_JournalHead,		/* Pins bh->b_private and jh->b_bh */
	BH_Unshadow,		/* Dummy bit, for BJ_Shadow wakeup filtering */
};

BUFFER_FNS(JBD, jbd)
BUFFER_FNS(JWrite, jwrite)
BUFFER_FNS(JBDDirty, jbddirty)
TAS_BUFFER_FNS(JBDDirty, jbddirty)
BUFFER_FNS(Revoked, revoked)
TAS_BUFFER_FNS(Revoked, revoked)
BUFFER_FNS(RevokeValid, revokevalid)
TAS_BUFFER_FNS(RevokeValid, revokevalid)
BUFFER_FNS(Freed, freed)

static inline struct buffer_head *jh2bh(struct journal_head *jh)
{
	return jh->b_bh;
}

static inline struct journal_head *bh2jh(struct buffer_head *bh)
{
	return bh->b_private;
}

static inline void jbd_lock_bh_state(struct buffer_head *bh)
{
	bit_spin_lock(BH_State, &bh->b_state);
}

static inline int jbd_trylock_bh_state(struct buffer_head *bh)
{
	return bit_spin_trylock(BH_State, &bh->b_state);
}

static inline int jbd_is_locked_bh_state(struct buffer_head *bh)
{
	return bit_spin_is_locked(BH_State, &bh->b_state);
}

static inline void jbd_unlock_bh_state(struct buffer_head *bh)
{
	bit_spin_unlock(BH_State, &bh->b_state);
}

static inline void jbd_lock_bh_journal_head(struct buffer_head *bh)
{
	bit_spin_lock(BH_JournalHead, &bh->b_state);
}

static inline void jbd_unlock_bh_journal_head(struct buffer_head *bh)
{
	bit_spin_unlock(BH_JournalHead, &bh->b_state);
}

struct jbd_revoke_table_s;

/**
 * struct handle_s - this is the concrete type associated with handle_t.
 * @h_transaction: Which compound transaction is this update a part of?
 * @h_buffer_credits: Number of remaining buffers we are allowed to dirty.
 * @h_ref: Reference count on this handle
 * @h_err: Field for caller's use to track errors through large fs operations
 * @h_sync: flag for sync-on-close
 * @h_jdata: flag to force data journaling
 * @h_aborted: flag indicating fatal error on handle
 * @h_lockdep_map: lockdep info for debugging lock problems
 */
struct handle_s
{
	/* Which compound transaction is this update a part of? */
	transaction_t		*h_transaction; 	/* 本原子操作属于哪个transaction */

	/* Number of remaining buffers we are allowed to dirty: */
	int			h_buffer_credits; 	/* 本原子操作的额度，即可以包含的磁盘块数 */

	/* Reference count on this handle */
	int			h_ref; 			/* 引用计数 */

	/* Field for caller's use to track errors through large fs */
	/* operations */
	int			h_err;

	/* Flags [no locking] */
	unsigned int	h_sync:		1;	/* sync-on-close *//* 表示同步，
						意思是处理完该原子操作后，立即将所属的transaction提交 */
	unsigned int	h_jdata:	1;	/* force data journaling */
	unsigned int	h_aborted:	1;	/* fatal error on handle */

#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	h_lockdep_map;
#endif
};


/* The transaction_t type is the guts of the journaling mechanism.  It
 * tracks a compound transaction through its various states:
 *
 * RUNNING:	accepting new updates
 * LOCKED:	Updates still running but we don't accept new ones
 * RUNDOWN:	Updates are tidying up but have finished requesting
 *		new buffers to modify (state not used for now)
 * FLUSH:       All updates complete, but we are still writing to disk
 * COMMIT:      All data on disk, writing commit record
 * FINISHED:	We still have to keep the transaction for checkpointing.
 *
 * The transaction keeps track of all of the buffers modified by a
 * running transaction, and all of the buffers committed but not yet
 * flushed to home for finished transactions.
 */

/*
 * Lock ranking:
 *
 *    j_list_lock
 *      ->jbd_lock_bh_journal_head()	(This is "innermost")
 *
 *    j_state_lock
 *    ->jbd_lock_bh_state()
 *
 *    jbd_lock_bh_state()
 *    ->j_list_lock
 *
 *    j_state_lock
 *    ->t_handle_lock
 *
 *    j_state_lock
 *    ->j_list_lock			(journal_unmap_buffer)
 *
 */

struct transaction_s
{
	/* Pointer to the journal for this transaction. [no locking] */
	journal_t		*t_journal; 	/* 指向所属的journal */

	/* Sequence number for this transaction [no locking] */
	tid_t			t_tid; 		/* 本事务的序号 */

	/*
	 * Transaction's current state
	 * [no locking - only kjournald alters this]
	 * [j_list_lock] guards transition of a transaction into T_FINISHED
	 * state and subsequent call of __journal_drop_transaction()
	 * FIXME: needs barriers
	 * KLUDGE: [use j_state_lock]
	 */
	enum {
		T_RUNNING, 	/* 正在运行的事务,一个journal只有一个正在运行的事务 */
		T_LOCKED, 	/* 表示不能再向该事务加入handle, 但已加入的handle可能还未完成 */
		T_RUNDOWN, 	/* 没用该状态 */
		T_FLUSH, 	/* 事务中的handle已经全部完成 */
		T_COMMIT, 	/* 事务正在进行提交 */
		T_FINISHED 	/* 事务已经提交到日志 */
	}			t_state; 	/* 事务的状态 */

	/*
	 * Where in the log does this transaction's commit start? [no locking]
	 */
	unsigned int		t_log_start; 	/* log中本transaction_t从日志中哪个块开始 */

	/* Number of buffers on the t_buffers list [j_list_lock] */
	int			t_nr_buffers; 	/* 本transaction_t中t_buffers队列中缓冲区的个数 
						 * 即元数据缓冲区的个数
						 */

	/*
	 * Doubly-linked circular list of all buffers reserved but not yet
	 * modified by this transaction [j_list_lock]
	 */
	struct journal_head	*t_reserved_list;  /* 对应BJ_Reserved */
				/* 被本transaction保留，但是并未修改的缓冲区组成的双向循环队列 */

	/*
	 * Doubly-linked circular list of all buffers under writeout during
	 * commit [j_list_lock]
	 */
	struct journal_head	*t_locked_list; /* 对应BJ_Locked */
				/* 由提交时所有正在被写出的、被锁住的数据缓冲区组成的双向循环链表 */

	/*
	 * Doubly-linked circular list of all metadata buffers owned by this
	 * transaction [j_list_lock]
	 */
	struct journal_head	*t_buffers; 	/* 对应BJ_Metadata */
				/* 元数据块缓冲区链表,这里面都是宝贵的元数据 */

	/*
	 * Doubly-linked circular list of all data buffers still to be
	 * flushed before this transaction can be committed [j_list_lock]
	 */
	struct journal_head	*t_sync_datalist; /* 对应BJ_SyncData */
				/* 本transaction_t被提交之前，
			 	需要被刷新到磁盘上的数据块（非元数据块）组成的双向链表。
	 			因为在ordered模式，我们要保证先刷新数据块，再刷新元数据块。*/

	/*
	 * Doubly-linked circular list of all forget buffers (superseded
	 * buffers which we can un-checkpoint once this transaction commits)
	 * [j_list_lock]
	 */
	struct journal_head	*t_forget; 	/* 对应BJ_Forget */	
				/* 被遗忘的缓冲区的链表。
				 当本transaction提交后，可以un-checkpointed的缓冲区。
				 这种情况是这样：
				 一个缓冲区正在被checkpointed，但是后来又调用journal_forget(),
				 此时以前的checkpointed项就没有用了。
				 此时需要在这里记录下来这个缓冲区，
				 然后un-checkpointed这个缓冲区。*/

	/*
	 * Doubly-linked circular list of all buffers still to be flushed before
	 * this transaction can be checkpointed. [j_list_lock]
	 */
	struct journal_head	*t_checkpoint_list; 	/* 本transaction_t可被checkpointed之前，
						 需要被刷新到磁盘上的所有缓冲区组成的双向链表。
	 				  	 这里面应该只包括元数据缓冲区。*/

	/*
	 * Doubly-linked circular list of all buffers submitted for IO while
	 * checkpointing. [j_list_lock]
	 */
	struct journal_head	*t_checkpoint_io_list; 	/* checkpointing时，
						已提交进行IO操作的所有缓冲区组成的链表 */

	/*
	 * Doubly-linked circular list of temporary buffers currently undergoing
	 * IO in the log [j_list_lock]
	 */
	struct journal_head	*t_iobuf_list; 		/* 对应BJ_IO */
				/* 进行临时性IO的元数据缓冲区的双向链表 */

	/*
	 * Doubly-linked circular list of metadata buffers being shadowed by log
	 * IO.  The IO buffers on the iobuf list and the shadow buffers on this
	 * list match each other one for one at all times. [j_list_lock]
	 */
	struct journal_head	*t_shadow_list;  	/* 对应BJ_Shadow */
				/* 被日志IO复制（拷贝）过的元数据缓冲区组成的双向循环链表
				t_iobuf_list 上的缓冲区始终与t_shadow_list上的缓冲区一一对应。
				实际上，当一个元数据块缓冲区要被写到日志中时，数据会被复制一份，
				放到新的缓冲区中。新缓冲区会进入t_iobuf_list队列，
				而原来的缓冲区会进入t_shadow_list队列。 */

	/*
	 * Doubly-linked circular list of control buffers being written to the
	 * log. [j_list_lock]
	 */
	struct journal_head	*t_log_list;  	/* 对应BJ_LogCtl */
				/* 正在写入log的起控制作用的缓冲区组成的链表 
				 * 包括描述符块、取消块
				 */

	/*
	 * Protects info related to handles
	 */
	spinlock_t		t_handle_lock; /* 保护handle的锁 */

	/*
	 * Number of outstanding updates running on this transaction
	 * [t_handle_lock]
	 */
	int			t_updates; /* 与本transaction相关联的外部更新的次数
				实际上是正在使用本transaction的handle的数量
				当journal_start时，t_updates++
				当journal_stop时，t_updates--
				t_updates == 0，表示没有handle正在使用该transaction，
				此时transaction处于一种可提交状态！*/

	/*
	 * Number of buffers reserved for use by all handles in this transaction
	 * handle but not yet modified. [t_handle_lock]
	 */
	int			t_outstanding_credits; /* 本事务预留的额度 */

	/*
	 * Forward and backward links for the circular list of all transactions
	 * awaiting checkpoint. [j_list_lock]
	 */
	transaction_t		*t_cpnext, *t_cpprev; /* 用于在checkpoint队列上组成链表 */

	/*
	 * When will the transaction expire (become due for commit), in jiffies?
	 * [no locking]
	 */
	unsigned long		t_expires;

	/*
	 * When this transaction started, in nanoseconds [no locking]
	 */
	ktime_t			t_start_time;

	/*
	 * How many handles used this transaction? [t_handle_lock]
	 */
	int t_handle_count; 	/* 本transaction_t有多少个handle_t */

	/*
	 * This transaction is being forced and some process is
	 * waiting for it to finish.
	 */
	unsigned int t_synchronous_commit:1; /* 本transaction已被逼迫了，有进程在等待它的完成。 */
};

/**
 * struct journal_s - this is the concrete type associated with journal_t.
 * @j_flags:  General journaling state flags
 * @j_errno:  Is there an outstanding uncleared error on the journal (from a
 *     prior abort)?
 * @j_sb_buffer: First part of superblock buffer
 * @j_superblock: Second part of superblock buffer
 * @j_format_version: Version of the superblock format
 * @j_state_lock: Protect the various scalars in the journal
 * @j_barrier_count:  Number of processes waiting to create a barrier lock
 * @j_barrier: The barrier lock itself
 * @j_running_transaction: The current running transaction..
 * @j_committing_transaction: the transaction we are pushing to disk
 * @j_checkpoint_transactions: a linked circular list of all transactions
 *  waiting for checkpointing
 * @j_wait_transaction_locked: Wait queue for waiting for a locked transaction
 *  to start committing, or for a barrier lock to be released
 * @j_wait_logspace: Wait queue for waiting for checkpointing to complete
 * @j_wait_done_commit: Wait queue for waiting for commit to complete
 * @j_wait_checkpoint:  Wait queue to trigger checkpointing
 * @j_wait_commit: Wait queue to trigger commit
 * @j_wait_updates: Wait queue to wait for updates to complete
 * @j_checkpoint_mutex: Mutex for locking against concurrent checkpoints
 * @j_head: Journal head - identifies the first unused block in the journal
 * @j_tail: Journal tail - identifies the oldest still-used block in the
 *  journal.
 * @j_free: Journal free - how many free blocks are there in the journal?
 * @j_first: The block number of the first usable block
 * @j_last: The block number one beyond the last usable block
 * @j_dev: Device where we store the journal
 * @j_blocksize: blocksize for the location where we store the journal.
 * @j_blk_offset: starting block offset for into the device where we store the
 *     journal
 * @j_fs_dev: Device which holds the client fs.  For internal journal this will
 *     be equal to j_dev
 * @j_maxlen: Total maximum capacity of the journal region on disk.
 * @j_list_lock: Protects the buffer lists and internal buffer state.
 * @j_inode: Optional inode where we store the journal.  If present, all journal
 *     block numbers are mapped into this inode via bmap().
 * @j_tail_sequence:  Sequence number of the oldest transaction in the log
 * @j_transaction_sequence: Sequence number of the next transaction to grant
 * @j_commit_sequence: Sequence number of the most recently committed
 *  transaction
 * @j_commit_request: Sequence number of the most recent transaction wanting
 *     commit
 * @j_uuid: Uuid of client object.
 * @j_task: Pointer to the current commit thread for this journal
 * @j_max_transaction_buffers:  Maximum number of metadata buffers to allow in a
 *     single compound commit transaction
 * @j_commit_interval: What is the maximum transaction lifetime before we begin
 *  a commit?
 * @j_commit_timer:  The timer used to wakeup the commit thread
 * @j_revoke_lock: Protect the revoke table
 * @j_revoke: The revoke table - maintains the list of revoked blocks in the
 *     current transaction.
 * @j_revoke_table: alternate revoke tables for j_revoke
 * @j_wbuf: array of buffer_heads for journal_commit_transaction
 * @j_wbufsize: maximum number of buffer_heads allowed in j_wbuf, the
 *	number that will fit in j_blocksize
 * @j_last_sync_writer: most recent pid which did a synchronous write
 * @j_average_commit_time: the average amount of time in nanoseconds it
 *	takes to commit a transaction to the disk.
 * @j_private: An opaque pointer to fs-private information.
 */

struct journal_s
{
	/* General journaling state flags [j_state_lock] */
	unsigned long		j_flags; 	/* journal的状态 */

	/*
	 * Is there an outstanding uncleared error on the journal (from a prior
	 * abort)? [j_state_lock]
	 */
	int			j_errno;

	/* The superblock buffer */
	struct buffer_head	*j_sb_buffer; 	/* 指向日志超级块缓冲区 */
	journal_superblock_t	*j_superblock;

	/* Version of the superblock format */
	int			j_format_version;

	/*
	 * Protect the various scalars in the journal
	 */
	spinlock_t		j_state_lock;

	/*
	 * Number of processes waiting to create a barrier lock [j_state_lock]
	 */
	int			j_barrier_count; /* 有多少个进程正在等待创建一个barrier lock
						这个变量是由j_state_lock来保护的*/

	/* The barrier lock itself */
	struct mutex		j_barrier; 	/* 互斥锁 */

	/*
	 * Transactions: The current running transaction...
	 * [j_state_lock] [caller holding open handle]
	 */
	transaction_t		*j_running_transaction; /* 指向正在运行的transaction */

	/*
	 * the transaction we are pushing to disk
	 * [j_state_lock] [caller holding open handle]
	 */
	transaction_t		*j_committing_transaction; /* 指向正在提交的transaction */

	/*
	 * ... and a linked circular list of all transactions waiting for
	 * checkpointing. [j_list_lock]
	 */
	transaction_t		*j_checkpoint_transactions; /* 仍在等待进行checkpoint操作的所有事务
				组成的循环队列, 一旦一个transaction执行checkpoint 完成，则从此队列删除。
				第一项是最旧的transaction，以此类推。*/

	/*
	 * Wait queue for waiting for a locked transaction to start committing,
	 * or for a barrier lock to be released
	 */
	wait_queue_head_t	j_wait_transaction_locked; /* 等待一个已上锁的transaction_t开始提交，
								或者一个barrier 锁被释放。*/

	/* Wait queue for waiting for checkpointing to complete */
	wait_queue_head_t	j_wait_logspace; /* 等待checkpointing完成以释放日志空间的等待队列 */

	/* Wait queue for waiting for commit to complete */
	wait_queue_head_t	j_wait_done_commit; 	/* 等待提交完成的等待队列 */

	/* Wait queue to trigger checkpointing */
	wait_queue_head_t	j_wait_checkpoint;

	/* Wait queue to trigger commit */
	wait_queue_head_t	j_wait_commit; /* 等待进行提交的的等待队列 */

	/* Wait queue to wait for updates to complete */
	wait_queue_head_t	j_wait_updates; /* 等待handle完成的等待队列 */

	/* Semaphore for locking against concurrent checkpoints */
	struct mutex		j_checkpoint_mutex; /* 保护checkpoint队列的互斥锁。 */

	/*
	 * Journal head: identifies the first unused block in the journal.
	 * [j_state_lock]
	 */
	unsigned int		j_head; /* journal中第一个未使用的块 */

	/*
	 * Journal tail: identifies the oldest still-used block in the journal.
	 * [j_state_lock]
	 */
	unsigned int		j_tail; /* journal中仍在使用的最旧的块号
					如果这个值为0，则整个journal是空的。*/
					/* 日志恢复时，从j_tail块号中存储的事务开始恢复，
					 * 该事务对应j_tail_sequence事务ID
					 *
					 * 在更新日志超级块时，将j_tail赋值给
					 * journal_superblock_s->s_start
					 */

	/*
	 * Journal free: how many free blocks are there in the journal?
	 * [j_state_lock]
	 */
	unsigned int		j_free; 	/* 日志空闲的块数目 */

	/*
	 * Journal start and end: the block numbers of the first usable block
	 * and one beyond the last usable block in the journal. [j_state_lock]
	 */
	/* 这两个是文件系统格式化以后就保存到超级块中的不变的量。
	 * 日志块的范围[j_first, j_last)
	 * 来自于journal_superblock_t
	 */
	unsigned int		j_first;
	unsigned int		j_last;

	/*
	 * Device, blocksize and starting block offset for the location where we
	 * store the journal.
	 */
	struct block_device	*j_dev;
	int			j_blocksize;
	unsigned int		j_blk_offset; /* 本journal相对与设备的块偏移量 */

	/*
	 * Device which holds the client fs.  For internal journal this will be
	 * equal to j_dev.
	 */
	struct block_device	*j_fs_dev; /* 日志维护的文件系统的块设备，
					如果是文件系统内的日志则与j_dev一致 */

	/* Total maximum capacity of the journal region on disk. */
	unsigned int		j_maxlen; /* 磁盘上journal的最大块数 */

	/*
	 * Protects the buffer lists and internal buffer state.
	 */
	spinlock_t		j_list_lock;

	/* Optional inode where we store the journal.  If present, all */
	/* journal block numbers are mapped into this inode via */
	/* bmap(). */
	struct inode		*j_inode;

	/*
	 * Sequence number of the oldest transaction in the log [j_state_lock]
	 */
	tid_t			j_tail_sequence; /* 日志中最旧的事务的序号 */
				/* 即事务已经提交到日志中，但还未被checkpoint的最早的事务ID
				 * 日志恢复时,从j_tail_sequence的事务开始恢复,直到遇到一个
				 * 没有提交块的事务，将这段区间的数据写入到磁盘原始的位置中.
				 *
				 * 在更新日志超级块时，将j_tail_sequence赋值给
				 * journal_superblock_s->s_sequence
				 */

	/*
	 * Sequence number of the next transaction to grant [j_state_lock]
	 */
	tid_t			j_transaction_sequence; /* 下一个授权的事务的顺序号 */
							/* 即下一个要分配的事务的ID号 */

	/*
	 * Sequence number of the most recently committed transaction
	 * [j_state_lock].
	 */
	tid_t			j_commit_sequence; /* 最近提交的transaction的顺序号 */

	/*
	 * Sequence number of the most recent transaction wanting commit
	 * [j_state_lock]
	 */
	tid_t			j_commit_request; /* 最近想申请提交的transaction的编号。
				如果一个transaction想提交，则把自己的编号赋值给j_commit_request，
				然后kjournald会择机进行处理*/

	/*
	 * Journal uuid: identifies the object (filesystem, LVM volume etc)
	 * backed by this journal.  This will eventually be replaced by an array
	 * of uuids, allowing us to index multiple devices within a single
	 * journal and to perform atomic updates across them.
	 */
	__u8			j_uuid[16]; 	/* 分区的UUID */

	/* Pointer to the current commit thread for this journal */
	struct task_struct	*j_task; /* 本journal指向的内核线程 */

	/*
	 * Maximum number of metadata buffers to allow in a single compound
	 * commit transaction
	 */
	int			j_max_transaction_buffers; /* 一次提交允许的最多的元数据缓冲区块数 */

	/*
	 * What is the maximum transaction lifetime before we begin a commit?
	 */
	unsigned long		j_commit_interval; 	/* kjournald内核线程的间隔时间，为5秒钟 */

	/* The timer used to wakeup the commit thread: */
	struct timer_list	j_commit_timer; /* 用于唤醒提交日志的kjournald内核线程的定时器 */

	/*
	 * The revoke table: maintains the list of revoked blocks in the
	 * current transaction.  [j_revoke_lock]
	 */
	spinlock_t		j_revoke_lock; /* 保护revoke 哈希表 */
	struct jbd_revoke_table_s *j_revoke; /* 指向journal正在使用的revoke hash table */
	struct jbd_revoke_table_s *j_revoke_table[2]; /* 指向两个revoke hash table */
		/* jbd 设置两个hash表的原因：当一个正在运行的transaction要提交时，
		 * 与之相对应的revoke hash表也要提交。要提交revoke hash表，必须
		 * 把其中的数据冻结起来，不再被改动。此时，为了能使jbd能够继续接收revoke记录，则需
		 * 为journal设置另一个hash表。所以，jbd设置了两个hash表，供journal交替使用。
		 */

	/*
	 * array of bhs for journal_commit_transaction
	 */
	struct buffer_head	**j_wbuf; 	/* 指向描述符块页面 */
	int			j_wbufsize; 	/* 一个描述符块中可以记录的块数 */

	/*
	 * this is the pid of the last person to run a synchronous operation
	 * through the journal.
	 */
	pid_t			j_last_sync_writer;

	/*
	 * the average amount of time in nanoseconds it takes to commit a
	 * transaction to the disk.  [j_state_lock]
	 */
	u64			j_average_commit_time; 	/* 提交事务的平均时间 */

	/*
	 * An opaque pointer to fs-private information.  ext3 puts its
	 * superblock pointer here
	 */
	void *j_private; 	/* 指向ext3的superblock */
};

/*
 * Journal flag definitions
 */
#define JFS_UNMOUNT	0x001	/* Journal thread is being destroyed */
#define JFS_ABORT	0x002	/* Journaling has been aborted for errors. */
#define JFS_ACK_ERR	0x004	/* The errno in the sb has been acked */
#define JFS_FLUSHED	0x008	/* The journal superblock has been flushed */
#define JFS_LOADED	0x010	/* The journal superblock has been loaded */
#define JFS_BARRIER	0x020	/* Use IDE barriers */
#define JFS_ABORT_ON_SYNCDATA_ERR	0x040  /* Abort the journal on file
						* data write error in ordered
						* mode */

/*
 * Function declarations for the journaling transaction and buffer
 * management
 */

/* Filing buffers */
extern void journal_unfile_buffer(journal_t *, struct journal_head *);
extern void __journal_unfile_buffer(struct journal_head *);
extern void __journal_refile_buffer(struct journal_head *);
extern void journal_refile_buffer(journal_t *, struct journal_head *);
extern void __journal_file_buffer(struct journal_head *, transaction_t *, int);
extern void __journal_free_buffer(struct journal_head *bh);
extern void journal_file_buffer(struct journal_head *, transaction_t *, int);
extern void __journal_clean_data_list(transaction_t *transaction);

/* Log buffer allocation */
extern struct journal_head * journal_get_descriptor_buffer(journal_t *);
int journal_next_log_block(journal_t *, unsigned int *);

/* Commit management */
extern void journal_commit_transaction(journal_t *);

/* Checkpoint list management */
int __journal_clean_checkpoint_list(journal_t *journal);
int __journal_remove_checkpoint(struct journal_head *);
void __journal_insert_checkpoint(struct journal_head *, transaction_t *);

/* Buffer IO */
extern int
journal_write_metadata_buffer(transaction_t	  *transaction,
			      struct journal_head  *jh_in,
			      struct journal_head **jh_out,
			      unsigned int blocknr);

/* Transaction locking */
extern void		__wait_on_journal (journal_t *);

/*
 * Journal locking.
 *
 * We need to lock the journal during transaction state changes so that nobody
 * ever tries to take a handle on the running transaction while we are in the
 * middle of moving it to the commit phase.  j_state_lock does this.
 *
 * Note that the locking is completely interrupt unsafe.  We never touch
 * journal structures from interrupts.
 */

static inline handle_t *journal_current_handle(void)
{
	return current->journal_info;
}

/* The journaling code user interface:
 *
 * Create and destroy handles
 * Register buffer modifications against the current transaction.
 */

extern handle_t *journal_start(journal_t *, int nblocks);
extern int	 journal_restart (handle_t *, int nblocks);
extern int	 journal_extend (handle_t *, int nblocks);
extern int	 journal_get_write_access(handle_t *, struct buffer_head *);
extern int	 journal_get_create_access (handle_t *, struct buffer_head *);
extern int	 journal_get_undo_access(handle_t *, struct buffer_head *);
extern int	 journal_dirty_data (handle_t *, struct buffer_head *);
extern int	 journal_dirty_metadata (handle_t *, struct buffer_head *);
extern void	 journal_release_buffer (handle_t *, struct buffer_head *);
extern int	 journal_forget (handle_t *, struct buffer_head *);
extern void	 journal_sync_buffer (struct buffer_head *);
extern void	 journal_invalidatepage(journal_t *,
				struct page *, unsigned long);
extern int	 journal_try_to_free_buffers(journal_t *, struct page *, gfp_t);
extern int	 journal_stop(handle_t *);
extern int	 journal_flush (journal_t *);
extern void	 journal_lock_updates (journal_t *);
extern void	 journal_unlock_updates (journal_t *);

extern journal_t * journal_init_dev(struct block_device *bdev,
				struct block_device *fs_dev,
				int start, int len, int bsize);
extern journal_t * journal_init_inode (struct inode *);
extern int	   journal_update_format (journal_t *);
extern int	   journal_check_used_features
		   (journal_t *, unsigned long, unsigned long, unsigned long);
extern int	   journal_check_available_features
		   (journal_t *, unsigned long, unsigned long, unsigned long);
extern int	   journal_set_features
		   (journal_t *, unsigned long, unsigned long, unsigned long);
extern int	   journal_create     (journal_t *);
extern int	   journal_load       (journal_t *journal);
extern int	   journal_destroy    (journal_t *);
extern int	   journal_recover    (journal_t *journal);
extern int	   journal_wipe       (journal_t *, int);
extern int	   journal_skip_recovery	(journal_t *);
extern void	   journal_update_superblock	(journal_t *, int);
extern void	   journal_abort      (journal_t *, int);
extern int	   journal_errno      (journal_t *);
extern void	   journal_ack_err    (journal_t *);
extern int	   journal_clear_err  (journal_t *);
extern int	   journal_bmap(journal_t *, unsigned int, unsigned int *);
extern int	   journal_force_commit(journal_t *);

/*
 * journal_head management
 */
struct journal_head *journal_add_journal_head(struct buffer_head *bh);
struct journal_head *journal_grab_journal_head(struct buffer_head *bh);
void journal_remove_journal_head(struct buffer_head *bh);
void journal_put_journal_head(struct journal_head *jh);

/*
 * handle management
 */
extern struct kmem_cache *jbd_handle_cache;

static inline handle_t *jbd_alloc_handle(gfp_t gfp_flags)
{
	return kmem_cache_alloc(jbd_handle_cache, gfp_flags);
}

static inline void jbd_free_handle(handle_t *handle)
{
	kmem_cache_free(jbd_handle_cache, handle);
}

/* Primary revoke support */
#define JOURNAL_REVOKE_DEFAULT_HASH 256
extern int	   journal_init_revoke(journal_t *, int);
extern void	   journal_destroy_revoke_caches(void);
extern int	   journal_init_revoke_caches(void);

extern void	   journal_destroy_revoke(journal_t *);
extern int	   journal_revoke (handle_t *,
				unsigned int, struct buffer_head *);
extern int	   journal_cancel_revoke(handle_t *, struct journal_head *);
extern void	   journal_write_revoke_records(journal_t *,
						transaction_t *, int);

/* Recovery revoke support */
extern int	journal_set_revoke(journal_t *, unsigned int, tid_t);
extern int	journal_test_revoke(journal_t *, unsigned int, tid_t);
extern void	journal_clear_revoke(journal_t *);
extern void	journal_switch_revoke_table(journal_t *journal);

/*
 * The log thread user interface:
 *
 * Request space in the current transaction, and force transaction commit
 * transitions on demand.
 */

int __log_space_left(journal_t *); /* Called with journal locked */
int log_start_commit(journal_t *journal, tid_t tid);
int __log_start_commit(journal_t *journal, tid_t tid);
int journal_start_commit(journal_t *journal, tid_t *tid);
int journal_force_commit_nested(journal_t *journal);
int log_wait_commit(journal_t *journal, tid_t tid);
int log_do_checkpoint(journal_t *journal);

void __log_wait_for_space(journal_t *journal);
extern void	__journal_drop_transaction(journal_t *, transaction_t *);
extern int	cleanup_journal_tail(journal_t *);

/* Debugging code only: */

#define jbd_ENOSYS() \
do {								           \
	printk (KERN_ERR "JBD unimplemented function %s\n", __func__); \
	current->state = TASK_UNINTERRUPTIBLE;			           \
	schedule();						           \
} while (1)

/*
 * is_journal_abort
 *
 * Simple test wrapper function to test the JFS_ABORT state flag.  This
 * bit, when set, indicates that we have had a fatal error somewhere,
 * either inside the journaling layer or indicated to us by the client
 * (eg. ext3), and that we and should not commit any further
 * transactions.
 */

static inline int is_journal_aborted(journal_t *journal)
{
	return journal->j_flags & JFS_ABORT;
}

static inline int is_handle_aborted(handle_t *handle)
{
	if (handle->h_aborted)
		return 1;
	return is_journal_aborted(handle->h_transaction->t_journal);
}

static inline void journal_abort_handle(handle_t *handle)
{
	handle->h_aborted = 1;
}

#endif /* __KERNEL__   */

/* Comparison functions for transaction IDs: perform comparisons using
 * modulo arithmetic so that they work over sequence number wraps. */

static inline int tid_gt(tid_t x, tid_t y)
{
	int difference = (x - y);
	return (difference > 0);
}

static inline int tid_geq(tid_t x, tid_t y)
{
	int difference = (x - y);
	return (difference >= 0);
}

extern int journal_blocks_per_page(struct inode *inode);

/*
 * Return the minimum number of blocks which must be free in the journal
 * before a new transaction may be started.  Must be called under j_state_lock.
 */
static inline int jbd_space_needed(journal_t *journal)
{
	int nblocks = journal->j_max_transaction_buffers;
	if (journal->j_committing_transaction)
		nblocks += journal->j_committing_transaction->
					t_outstanding_credits;
	return nblocks;
}

/*
 * Definitions which augment the buffer_head layer
 */

/* journaling buffer types */
/* 以下journal_head的状态分别对应该journal_head放在事务的哪个链表上，
 * 对应关系参照函数 __journal_file_buffer */
#define BJ_None		0	/* Not journaled */
#define BJ_SyncData	1	/* Normal data: flush before commit */
#define BJ_Metadata	2	/* Normal journaled metadata */
#define BJ_Forget	3	/* Buffer superseded by this transaction */
#define BJ_IO		4	/* Buffer is for temporary IO use */
#define BJ_Shadow	5	/* Buffer contents being shadowed to the log */
#define BJ_LogCtl	6	/* Buffer contains log descriptors */
#define BJ_Reserved	7	/* Buffer is reserved for access by journal */
#define BJ_Locked	8	/* Locked for I/O during commit */
#define BJ_Types	9

extern int jbd_blocks_per_page(struct inode *inode);

#ifdef __KERNEL__

#define buffer_trace_init(bh)	do {} while (0)
#define print_buffer_fields(bh)	do {} while (0)
#define print_buffer_trace(bh)	do {} while (0)
#define BUFFER_TRACE(bh, info)	do {} while (0)
#define BUFFER_TRACE2(bh, bh2, info)	do {} while (0)
#define JBUFFER_TRACE(jh, info)	do {} while (0)

#endif	/* __KERNEL__ */

#endif	/* _LINUX_JBD_H */
