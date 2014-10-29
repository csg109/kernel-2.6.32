/*
 * linux/fs/jbd/recovery.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1999-2000 Red Hat Software --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal recovery routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

#ifndef __KERNEL__
#include "jfs_user.h"
#else
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/errno.h>
#include <linux/slab.h>
#endif

/*
 * Maintain information about the progress of the recovery job, so that
 * the different passes can carry information between them.
 */
struct recovery_info
{
	tid_t		start_transaction; 	/* 恢复的起始事务ID */
	tid_t		end_transaction; 	/* 恢复的最后事务ID(不包括本事务)
						 * 即end_transaction为没有提交块的事务
						 */

	int		nr_replays; 		/* 从日志中恢复块的计数 */
	int		nr_revokes; 		/* 取消块中记录块号的个数 */
	int		nr_revoke_hits; 	/* revoke块命中的次数 */
};

enum passtype {PASS_SCAN, PASS_REVOKE, PASS_REPLAY};
static int do_one_pass(journal_t *journal,
				struct recovery_info *info, enum passtype pass);
static int scan_revoke_records(journal_t *, struct buffer_head *,
				tid_t, struct recovery_info *);

#ifdef __KERNEL__

/* Release readahead buffers after use */
static void journal_brelse_array(struct buffer_head *b[], int n)
{
	while (--n >= 0)
		brelse (b[n]);
}


/*
 * When reading from the journal, we are going through the block device
 * layer directly and so there is no readahead being done for us.  We
 * need to implement any readahead ourselves if we want it to happen at
 * all.  Recovery is basically one long sequential read, so make sure we
 * do the IO in reasonably large chunks.
 *
 * This is not so critical that we need to be enormously clever about
 * the readahead size, though.  128K is a purely arbitrary, good-enough
 * fixed value.
 */

#define MAXBUF 8
static int do_readahead(journal_t *journal, unsigned int start)
{
	int err;
	unsigned int max, nbufs, next;
	unsigned int blocknr;
	struct buffer_head *bh;

	struct buffer_head * bufs[MAXBUF];

	/* Do up to 128K of readahead */
	max = start + (128 * 1024 / journal->j_blocksize);
	if (max > journal->j_maxlen)
		max = journal->j_maxlen;

	/* Do the readahead itself.  We'll submit MAXBUF buffer_heads at
	 * a time to the block device IO layer. */

	nbufs = 0;

	for (next = start; next < max; next++) {
		err = journal_bmap(journal, next, &blocknr);

		if (err) {
			printk (KERN_ERR "JBD: bad block at offset %u\n",
				next);
			goto failed;
		}

		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
		if (!bh) {
			err = -ENOMEM;
			goto failed;
		}

		if (!buffer_uptodate(bh) && !buffer_locked(bh)) {
			bufs[nbufs++] = bh;
			if (nbufs == MAXBUF) {
				ll_rw_block(READ, nbufs, bufs);
				journal_brelse_array(bufs, nbufs);
				nbufs = 0;
			}
		} else
			brelse(bh);
	}

	if (nbufs)
		ll_rw_block(READ, nbufs, bufs);
	err = 0;

failed:
	if (nbufs)
		journal_brelse_array(bufs, nbufs);
	return err;
}

#endif /* __KERNEL__ */


/*
 * Read a block from the journal
 */

static int jread(struct buffer_head **bhp, journal_t *journal,
		 unsigned int offset)
{
	int err;
	unsigned int blocknr;
	struct buffer_head *bh;

	*bhp = NULL;

	if (offset >= journal->j_maxlen) {
		printk(KERN_ERR "JBD: corrupted journal superblock\n");
		return -EIO;
	}

	err = journal_bmap(journal, offset, &blocknr);

	if (err) {
		printk (KERN_ERR "JBD: bad block at offset %u\n",
			offset);
		return err;
	}

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!bh)
		return -ENOMEM;

	if (!buffer_uptodate(bh)) {
		/* If this is a brand new buffer, start readahead.
                   Otherwise, we assume we are already reading it.  */
		if (!buffer_req(bh))
			do_readahead(journal, offset);
		wait_on_buffer(bh);
	}

	if (!buffer_uptodate(bh)) {
		printk (KERN_ERR "JBD: Failed to read block at offset %u\n",
			offset);
		brelse(bh);
		return -EIO;
	}

	*bhp = bh;
	return 0;
}


/*
 * Count the number of in-use tags in a journal descriptor block.
 */
/* 计算描述块中有几个索引块 */
static int count_tags(struct buffer_head *bh, int size)
{
	char *			tagp;
	journal_block_tag_t *	tag;
	int			nr = 0;

	tagp = &bh->b_data[sizeof(journal_header_t)];

	while ((tagp - bh->b_data + sizeof(journal_block_tag_t)) <= size) {
		tag = (journal_block_tag_t *) tagp;

		nr++;
		tagp += sizeof(journal_block_tag_t);

		/* 第一个索引块之后跟了一个16字节的UUID */
		if (!(tag->t_flags & cpu_to_be32(JFS_FLAG_SAME_UUID)))
			tagp += 16;

		/* 最后一个索引块 */
		if (tag->t_flags & cpu_to_be32(JFS_FLAG_LAST_TAG))
			break;
	}

	return nr;
}


/* Make sure we wrap around the log correctly! */
#define wrap(journal, var)						\
do {									\
	if (var >= (journal)->j_last)					\
		var -= ((journal)->j_last - (journal)->j_first);	\
} while (0)

/**
 * journal_recover - recovers a on-disk journal
 * @journal: the journal to recover
 *
 * The primary function for recovering the log contents when mounting a
 * journaled device.
 *
 * Recovery is done in three passes.  In the first pass, we look for the
 * end of the log.  In the second, we assemble the list of revoke
 * blocks.  In the third and final pass, we replay any un-revoked blocks
 * in the log.
 */
/* 进行实际的日志恢复操作 */
int journal_recover(journal_t *journal)
{
	int			err, err2;
	journal_superblock_t *	sb;

	struct recovery_info	info;

	memset(&info, 0, sizeof(info));
	sb = journal->j_superblock;

	/*
	 * The journal superblock's s_start field (the current log head)
	 * is always zero if, and only if, the journal was cleanly
	 * unmounted.
	 */

	if (!sb->s_start) {
		/* 如果文件系统是被正常卸载的，则不需要恢复。
		 * 递增j_transaction_sequence，使整个日志无效。*/
		jbd_debug(1, "No recovery required, last transaction %d\n",
			  be32_to_cpu(sb->s_sequence));
		journal->j_transaction_sequence = be32_to_cpu(sb->s_sequence) + 1;
		return 0;
	}

	/* 恢复步骤1：PASS_SCAN
	 * 这个步骤主要的作用是找到日志的起点和终点，
	 * 将起点和终点事务的ID分别记录在info->start_transaction, info->end_transaction中
	 * 注意日志空间可看做一个环形结构。
	 */
	err = do_one_pass(journal, &info, PASS_SCAN);

	/* 恢复步骤2：PASS_REVOKE
	 * 这个步骤主要的作用找到revoke块，并把信息读入内存的revoke hash table。
	 */
	if (!err)
		err = do_one_pass(journal, &info, PASS_REVOKE);

	/* 恢复步骤3：PASS_REPLAY
	 * 日志恢复的主要步骤
	 * 这个步骤主要的作用是根据描述符块的指示，
	 * 将日志中的数据块写回到磁盘的原始位置上。
	 *
	 * 系统意外崩溃时，有一部分元数据块已经写到日志中了，但是尚未写回到磁盘的原始位置上。
	 * replay的作用就是将日志中的元数据块再重新写回到磁盘的原始位置
	 */
	if (!err)
		err = do_one_pass(journal, &info, PASS_REPLAY);

	jbd_debug(1, "JBD: recovery, exit status %d, "
		  "recovered transactions %u to %u\n",
		  err, info.start_transaction, info.end_transaction);
	jbd_debug(1, "JBD: Replayed %d and revoked %d/%d blocks\n",
		  info.nr_replays, info.nr_revoke_hits, info.nr_revokes);

	/* Restart the log at the next transaction ID, thus invalidating
	 * any existing commit records in the log. */
	/* 恢复完成，递增j_transaction_sequence，使整个日志无效 */
	journal->j_transaction_sequence = ++info.end_transaction;

	/* 清空内存中的revoke hash table */
	journal_clear_revoke(journal);
	/* 同步日志所在的设备 */
	err2 = sync_blockdev(journal->j_fs_dev);
	if (!err)
		err = err2;

	return err;
}

/**
 * journal_skip_recovery - Start journal and wipe exiting records
 * @journal: journal to startup
 *
 * Locate any valid recovery information from the journal and set up the
 * journal structures in memory to ignore it (presumably because the
 * caller has evidence that it is out of date).
 * This function does'nt appear to be exorted..
 *
 * We perform one pass over the journal to allow us to tell the user how
 * much recovery information is being erased, and to let us initialise
 * the journal transaction sequence numbers to the next unused ID.
 */
int journal_skip_recovery(journal_t *journal)
{
	int			err;
	journal_superblock_t *	sb;

	struct recovery_info	info;

	memset (&info, 0, sizeof(info));
	sb = journal->j_superblock;

	err = do_one_pass(journal, &info, PASS_SCAN);

	if (err) {
		printk(KERN_ERR "JBD: error %d scanning journal\n", err);
		++journal->j_transaction_sequence;
	} else {
#ifdef CONFIG_JBD_DEBUG
		int dropped = info.end_transaction - be32_to_cpu(sb->s_sequence);
#endif
		jbd_debug(1,
			  "JBD: ignoring %d transaction%s from the journal.\n",
			  dropped, (dropped == 1) ? "" : "s");
		journal->j_transaction_sequence = ++info.end_transaction;
	}

	journal->j_tail = 0;
	return err;
}

static int do_one_pass(journal_t *journal,
			struct recovery_info *info, enum passtype pass)
{
	unsigned int		first_commit_ID, next_commit_ID;
	unsigned int		next_log_block;
	int			err, success = 0;
	journal_superblock_t *	sb;
	journal_header_t *	tmp;
	struct buffer_head *	bh;
	unsigned int		sequence;
	int			blocktype;

	/* Precompute the maximum metadata descriptors in a descriptor block */
	int			MAX_BLOCKS_PER_DESC;
	/* 计算一个描述符块中最多有几个索引块 */
	MAX_BLOCKS_PER_DESC = ((journal->j_blocksize-sizeof(journal_header_t))
			       / sizeof(journal_block_tag_t));

	/*
	 * First thing is to establish what we expect to find in the log
	 * (in terms of transaction IDs), and where (in terms of log
	 * block offsets): query the superblock.
	 */

	sb = journal->j_superblock;
	next_commit_ID = be32_to_cpu(sb->s_sequence);
	next_log_block = be32_to_cpu(sb->s_start); /* next_log_block表示要在日志中读的下一个块的块号 */

	first_commit_ID = next_commit_ID;
	if (pass == PASS_SCAN)
		info->start_transaction = first_commit_ID;

	jbd_debug(1, "Starting recovery pass %d\n", pass);

	/*
	 * Now we walk through the log, transaction by transaction,
	 * making sure that each transaction has a commit block in the
	 * expected place.  Each complete transaction gets replayed back
	 * into the main filesystem.
	 */

	while (1) { /* 遍历所有的日志块 */
		int			flags;
		char *			tagp;
		journal_block_tag_t *	tag;
		struct buffer_head *	obh;
		struct buffer_head *	nbh;

		cond_resched();

		/* If we already know where to stop the log traversal,
		 * check right now that we haven't gone past the end of
		 * the log. */

		if (pass != PASS_SCAN)
			/* 遇到最后一个事务跳出 */
			if (tid_geq(next_commit_ID, info->end_transaction))
				break;

		jbd_debug(2, "Scanning for sequence ID %u at %u/%u\n",
			  next_commit_ID, next_log_block, journal->j_last);

		/* Skip over each chunk of the transaction looking
		 * either the next descriptor block or the final commit
		 * record. */

		jbd_debug(3, "JBD: checking block %u\n", next_log_block);
		/* 读入日志中的下一个块 */
		err = jread(&bh, journal, next_log_block);
		if (err)
			goto failed;

		next_log_block++;
		wrap(journal, next_log_block); /* 注意日志是个环形结构 */

		/* What kind of buffer is it?
		 *
		 * If it is a descriptor block, check that it has the
		 * expected sequence number.  Otherwise, we're all done
		 * here. */

		tmp = (journal_header_t *)bh->b_data;
		/* 如果该块不是日志的描述块，则说明已经处理完了，退出 */
		if (tmp->h_magic != cpu_to_be32(JFS_MAGIC_NUMBER)) {
			brelse(bh);
			break;
		}

		blocktype = be32_to_cpu(tmp->h_blocktype);
		sequence = be32_to_cpu(tmp->h_sequence);
		jbd_debug(3, "Found magic %d, sequence %d\n",
			  blocktype, sequence);

		if (sequence != next_commit_ID) { /* 如果序号不对，退出 */
			brelse(bh);
			break;
		}

		/* OK, we have a valid descriptor block which matches
		 * all of the sequence number checks.  What are we going
		 * to do with it?  That depends on the pass... */

		/* 根据描述块的类型，进行相应的处理 */
		switch(blocktype) {
		case JFS_DESCRIPTOR_BLOCK: 	/* 描述符块 */
			/* If it is a valid descriptor block, replay it
			 * in pass REPLAY; otherwise, just skip over the
			 * blocks it describes. */
			/* 第一次do_one_pass()在PASS_SCAN中，
			 * count_tags()函数会计算该描述符块中一共描述了多少个数据块的
			 * 对应关系(有几个索引块)，现在直接跳过数据块即可 
			 */
			if (pass != PASS_REPLAY) {
				next_log_block +=
					count_tags(bh, journal->j_blocksize);
				wrap(journal, next_log_block);
				brelse(bh);
				continue;
			}

			/* A descriptor block: we can now write all of
			 * the data blocks.  Yay, useful work is finally
			 * getting done here! */
			/* 下面的步骤在PASS_REPLAY中处理 */

			tagp = &bh->b_data[sizeof(journal_header_t)]; /* 指向第一个索引块 */
			/* 循环描述符块中的每个索引块 */
			while ((tagp - bh->b_data +sizeof(journal_block_tag_t))
			       <= journal->j_blocksize) {
				/* 处理这个描述符块。
				 * 将其中的数据块从日志中读出来，
				 * 根据指示写回到磁盘的原始位置
				 */
				unsigned int io_block;

				/* 从描述符块中取出一个journal_block_tag_t结构 */
				tag = (journal_block_tag_t *) tagp;
				flags = be32_to_cpu(tag->t_flags);

				/* io_block表示描述符块之后的日志中的一个数据块，
				 * 我们要把io_block中的数据写回到磁盘的原始位置。*/
				io_block = next_log_block++;
				wrap(journal, next_log_block);
				/* 读入io_block块的数据 */
				err = jread(&obh, journal, io_block);
				if (err) {
					/* Recover what we can, but
					 * report failure at the end. */
					success = err;
					printk (KERN_ERR
						"JBD: IO error %d recovering "
						"block %u in log\n",
						err, io_block);
				} else {
					unsigned int blocknr;

					J_ASSERT(obh != NULL);

					/* 磁盘原始位置在哪里？在t_blocknr 中。
					 * 故blocknr 表示日志中的该块对应的磁盘原始位置的块号
					 */
					blocknr = be32_to_cpu(tag->t_blocknr);

					/* If the block has been
					 * revoked, then we're all done
					 * here. */
					/* 判断blocknr 是否需要恢复，
					 * revoke 机制在这里起作用了！
					 */
					if (journal_test_revoke
					    (journal, blocknr,
					     next_commit_ID)) { /* 不需要恢复 */
						brelse(obh);
						++info->nr_revoke_hits;
						goto skip_write;
					}

					/* Find a buffer for the new
					 * data being restored */
					/* 读入blocknr对应的缓冲区 */
					nbh = __getblk(journal->j_fs_dev,
							blocknr,
							journal->j_blocksize);
					if (nbh == NULL) {
						printk(KERN_ERR
						       "JBD: Out of memory "
						       "during recovery.\n");
						err = -ENOMEM;
						brelse(bh);
						brelse(obh);
						goto failed;
					}

					lock_buffer(nbh);
					/* obh代表日志中的一块数据，
					 * nbh代表磁盘原始位置的一块数据，
					 * 进行数据拷贝！
					 */
					memcpy(nbh->b_data, obh->b_data,
							journal->j_blocksize);
					if (flags & JFS_FLAG_ESCAPE) { /* 处理转义块 */
						*((__be32 *)nbh->b_data) =
						cpu_to_be32(JFS_MAGIC_NUMBER);
					}

					BUFFER_TRACE(nbh, "marking dirty");
					set_buffer_uptodate(nbh);
					mark_buffer_dirty(nbh);
					BUFFER_TRACE(nbh, "marking uptodate");
					++info->nr_replays;
					/* ll_rw_block(WRITE, 1, &nbh); */
					unlock_buffer(nbh);
					brelse(obh);
					brelse(nbh);
				}

			skip_write:
				tagp += sizeof(journal_block_tag_t);
				/* 第一个索引项之后有16字节的UUID，需跳过 */
				if (!(flags & JFS_FLAG_SAME_UUID)) 
					tagp += 16;

				/* 最后一个索引项 */
				if (flags & JFS_FLAG_LAST_TAG)
					break;
			}

			brelse(bh);
			continue;

		case JFS_COMMIT_BLOCK: /* 提交块 */
			/* Found an expected commit block: not much to
			 * do other than move on to the next sequence
			 * number. */
			brelse(bh);
			next_commit_ID++;
			continue;

		case JFS_REVOKE_BLOCK: /* 取消块，只在取消步骤中处理 */
			/* If we aren't in the REVOKE pass, then we can
			 * just skip over this block. */
			if (pass != PASS_REVOKE) {
				brelse(bh);
				continue;
			}

			/* 现在在PASS_REVOKE步骤中，
			 * 调用scan_revoke_records()从取消块中读入数据，
			 * 构造内存中的revoke hash table
			 */
			err = scan_revoke_records(journal, bh,
						  next_commit_ID, info);
			brelse(bh);
			if (err)
				goto failed;
			continue;

		default:
			jbd_debug(3, "Unrecognised magic %d, end of scan.\n",
				  blocktype);
			brelse(bh);
			goto done;
		}
	}

 done:
	/*
	 * We broke out of the log scan loop: either we came to the
	 * known end of the log or we found an unexpected block in the
	 * log.  If the latter happened, then we know that the "current"
	 * transaction marks the end of the valid log.
	 */

	if (pass == PASS_SCAN)
		info->end_transaction = next_commit_ID;
	else {
		/* It's really bad news if different passes end up at
		 * different places (but possible due to IO errors). */
		if (info->end_transaction != next_commit_ID) {
			printk (KERN_ERR "JBD: recovery pass %d ended at "
				"transaction %u, expected %u\n",
				pass, next_commit_ID, info->end_transaction);
			if (!success)
				success = -EIO;
		}
	}

	return success;

 failed:
	return err;
}


/* Scan a revoke record, marking all blocks mentioned as revoked. */
/* 将一个取消块中的信息填入内存中的revoke hash table。*/
static int scan_revoke_records(journal_t *journal, struct buffer_head *bh,
			       tid_t sequence, struct recovery_info *info)
{
	journal_revoke_header_t *header;
	int offset, max;

	header = (journal_revoke_header_t *) bh->b_data;
	offset = sizeof(journal_revoke_header_t);
	max = be32_to_cpu(header->r_count); /* r_count 保存的是本取消块的界限 */

	while (offset < max) {
		unsigned int blocknr;
		int err;

		blocknr = be32_to_cpu(* ((__be32 *) (bh->b_data+offset))); /* 取得磁盘块号 */
		offset += 4;

		/* 将<blocknr, sequence>插入到revoke hash table表中 */
		err = journal_set_revoke(journal, blocknr, sequence);
		if (err)
			return err;
		++info->nr_revokes;
	}
	return 0;
}
