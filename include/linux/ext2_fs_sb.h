/*
 *  linux/include/linux/ext2_fs_sb.h
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/include/linux/minix_fs_sb.h
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#ifndef _LINUX_EXT2_FS_SB
#define _LINUX_EXT2_FS_SB

#include <linux/blockgroup_lock.h>
#include <linux/percpu_counter.h>
#include <linux/rbtree.h>

/* XXX Here for now... not interested in restructing headers JUST now */

/* data type for block offset of block group */
typedef int ext2_grpblk_t;

/* data type for filesystem-wide blocks number */
typedef unsigned long ext2_fsblk_t;

#define E2FSBLK "%lu"

struct ext2_reserve_window {
	ext2_fsblk_t		_rsv_start;	/* First byte reserved */
	ext2_fsblk_t		_rsv_end;	/* Last byte reserved or 0 */
};

struct ext2_reserve_window_node {
	struct rb_node	 	rsv_node;
	__u32			rsv_goal_size;  /* 预留窗口的预期长度 */
	__u32			rsv_alloc_hit;  /* 预分配的命中数 */
	struct ext2_reserve_window	rsv_window;
};

struct ext2_block_alloc_info {
	/* information about reservation window */
	struct ext2_reserve_window_node	rsv_window_node;
	/*
	 * was i_next_alloc_block in ext2_inode_info
	 * is the logical (file-relative) number of the
	 * most-recently-allocated block in this file.
	 * We use this for detecting linearly ascending allocation requests.
	 */
	__u32			last_alloc_logical_block;
	/*
	 * Was i_next_alloc_goal in ext2_inode_info
	 * is the *physical* companion to i_next_alloc_block.
	 * it the the physical block number of the block which was most-recentl
	 * allocated to this file.  This give us the goal (target) for the next
	 * allocation when we detect linearly ascending requests.
	 */
	ext2_fsblk_t		last_alloc_physical_block;
};

#define rsv_start rsv_window._rsv_start
#define rsv_end rsv_window._rsv_end

/*
 * second extended-fs super-block data in memory
 */
/* 用于存储与文件系统无关的数据成员所未能涵盖的信息，由struct super_block的成员s_fs_inof指向。 */
struct ext2_sb_info { 	
	unsigned long s_frag_size;	/* Size of a fragment in bytes */
	unsigned long s_frags_per_block;/* Number of fragments per block */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_frags_per_group;/* Number of fragments in a group */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block *//* 可以放在一个块中的组描述符的个数 */
	unsigned long s_groups_count;	/* Number of groups in the fs */ /* 分区中的块组数 */
	unsigned long s_overhead_last;  /* Last calculated overhead */ /* 上一次计算的管理数据的块数 */
	unsigned long s_blocks_last;    /* Last seen block count */ /* 上一次计算的可用块数 */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */ /* 指向包含磁盘超级块的缓冲区的缓冲区首部 */
	struct ext2_super_block * s_es;	/* Pointer to the super block in the buffer */ /* 指向磁盘超级块所在的缓冲区 */
	struct buffer_head ** s_group_desc; /* 指向包含分区中组描述符的缓冲区首部数组 */
	unsigned long  s_mount_opt; 	/* 装载选项 */
	unsigned long s_sb_block; 	/* 如果超级块不是从默认的块1读取，对应读取的块保存在s_sb_block中 */
	uid_t s_resuid;
	gid_t s_resgid;
	unsigned short s_mount_state; 	/* 装载状态 */
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits; 	/* 每块中组描述符数的log2, 即log2(s_desc_per_block) */
	int s_inode_size;
	int s_first_ino; 		/* 第一个分配的节点号 */
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	unsigned long s_dir_count; 	/* 目录的总数 */
	u8 *s_debts; 			/* 指向一个数组，每个数组项对应一个块组, orlov分配器使用该数组在一个块组中的文件和目录inode之间保持均衡 */
	struct percpu_counter s_freeblocks_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	/* root of the per fs reservation window tree */
	spinlock_t s_rsv_window_lock;
	struct rb_root s_rsv_window_root; 	/* ext2_reserve_window_node 的红黑树根节点 */
	struct ext2_reserve_window_node s_rsv_window_head;
};

static inline spinlock_t *
sb_bgl_lock(struct ext2_sb_info *sbi, unsigned int block_group)
{
	return bgl_lock_ptr(sbi->s_blockgroup_lock, block_group);
}

#endif	/* _LINUX_EXT2_FS_SB */
