/*
 * linux/fs/jbd/commit.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal commit routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <trace/events/jbd.h>

/*
 * Default IO end handler for temporary BJ_IO buffer_heads.
 */
static void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	unlock_buffer(bh);
}

/*
 * When an ext3-ordered file is truncated, it is possible that many pages are
 * not successfully freed, because they are attached to a committing transaction.
 * After the transaction commits, these pages are left on the LRU, with no
 * ->mapping, and with attached buffers.  These pages are trivially reclaimable
 * by the VM, but their apparent absence upsets the VM accounting, and it makes
 * the numbers in /proc/meminfo look odd.
 *
 * So here, we have a buffer which has just come off the forget list.  Look to
 * see if we can strip all buffers from the backing page.
 *
 * Called under journal->j_list_lock.  The caller provided us with a ref
 * against the buffer, and we drop that here.
 */
static void release_buffer_page(struct buffer_head *bh)
{
	struct page *page;

	if (buffer_dirty(bh))
		goto nope;
	if (atomic_read(&bh->b_count) != 1)
		goto nope;
	page = bh->b_page;
	if (!page)
		goto nope;
	if (page->mapping)
		goto nope;

	/* OK, it's a truncated page */
	if (!trylock_page(page))
		goto nope;

	page_cache_get(page);
	__brelse(bh);
	try_to_free_buffers(page);
	unlock_page(page);
	page_cache_release(page);
	return;

nope:
	__brelse(bh);
}

/*
 * Decrement reference counter for data buffer. If it has been marked
 * 'BH_Freed', release it and the page to which it belongs if possible.
 */
static void release_data_buffer(struct buffer_head *bh)
{
	if (buffer_freed(bh)) {
		clear_buffer_freed(bh);
		release_buffer_page(bh);
	} else
		put_bh(bh);
}

/*
 * Try to acquire jbd_lock_bh_state() against the buffer, when j_list_lock is
 * held.  For ranking reasons we must trylock.  If we lose, schedule away and
 * return 0.  j_list_lock is dropped in this case.
 */
static int inverted_lock(journal_t *journal, struct buffer_head *bh)
{
	if (!jbd_trylock_bh_state(bh)) {
		spin_unlock(&journal->j_list_lock);
		schedule();
		return 0;
	}
	return 1;
}

/* Done it all: now write the commit record.  We should have
 * cleaned up our previous buffers by now, so if we are in abort
 * mode we can now just skip the rest of the journal write
 * entirely.
 *
 * Returns 1 if the journal needs to be aborted or 0 on success
 */
/* 写一个提交块 */
static int journal_write_commit_record(journal_t *journal,
					transaction_t *commit_transaction)
{
	struct journal_head *descriptor;
	struct buffer_head *bh;
	journal_header_t *header;
	int ret;

	if (is_journal_aborted(journal))
		return 0;

	/* 从日志中分配一个块，作为提交块 */
	descriptor = journal_get_descriptor_buffer(journal);
	if (!descriptor)
		return 1;

	bh = jh2bh(descriptor);

	/* 设置提交块信息 */
	header = (journal_header_t *)(bh->b_data);
	header->h_magic = cpu_to_be32(JFS_MAGIC_NUMBER);
	header->h_blocktype = cpu_to_be32(JFS_COMMIT_BLOCK);
	header->h_sequence = cpu_to_be32(commit_transaction->t_tid);

	JBUFFER_TRACE(descriptor, "write commit block");
	set_buffer_dirty(bh);

	/* 同步将提交块写到日志中 */
	if (journal->j_flags & JFS_BARRIER)
		ret = __sync_dirty_buffer(bh, WRITE_SYNC | WRITE_FLUSH_FUA);
	else
		ret = sync_dirty_buffer(bh);

	put_bh(bh);		/* One for getblk() */
	/* 写入日志后，删除提交块 */
	journal_put_journal_head(descriptor);

	return (ret == -EIO);
}

static void journal_do_submit_data(struct buffer_head **wbuf, int bufs,
				   int write_op)
{
	int i;

	for (i = 0; i < bufs; i++) {
		wbuf[i]->b_end_io = end_buffer_write_sync;
		/* We use-up our safety reference in submit_bh() */
		submit_bh(write_op, wbuf[i]);
	}
}

/*
 *  Submit all the data buffers to disk
 */
/* 将与transaction相关联的数据块缓冲区先写回磁盘，ordered模式就是这样实现的。
 * 这些数据块缓冲区原来在BJ_SyncData队列上，现在会移动到BJ_Locked队列上
 * 本函数只是提出了写缓冲区的申请，但是并不保证缓冲区同步地写回磁盘
 */
static int journal_submit_data_buffers(journal_t *journal,
				       transaction_t *commit_transaction,
				       int write_op)
{
	struct journal_head *jh;
	struct buffer_head *bh;
	int locked;
	int bufs = 0;
	struct buffer_head **wbuf = journal->j_wbuf;
	int err = 0;

	/*
	 * Whenever we unlock the journal and sleep, things can get added
	 * onto ->t_sync_datalist, so we have to keep looping back to
	 * write_out_data until we *know* that the list is empty.
	 *
	 * Cleanup any flushed data buffers from the data list.  Even in
	 * abort mode, we want to flush this out as soon as possible.
	 */
write_out_data:
	cond_resched();
	spin_lock(&journal->j_list_lock);

	/* 依次处理每个缓冲区 */
	while (commit_transaction->t_sync_datalist) {
		jh = commit_transaction->t_sync_datalist;
		bh = jh2bh(jh);
		locked = 0;

		/* Get reference just to make sure buffer does not disappear
		 * when we are forced to drop various locks */
		get_bh(bh);
		/* If the buffer is dirty, we need to submit IO and hence
		 * we need the buffer lock. We try to lock the buffer without
		 * blocking. If we fail, we need to drop j_list_lock and do
		 * blocking lock_buffer().
		 */
		if (buffer_dirty(bh)) {
			if (!trylock_buffer(bh)) {
				BUFFER_TRACE(bh, "needs blocking lock");
				spin_unlock(&journal->j_list_lock);
				trace_jbd_do_submit_data(journal,
						     commit_transaction);
				/* Write out all data to prevent deadlocks */
				journal_do_submit_data(wbuf, bufs, write_op);
				bufs = 0;
				lock_buffer(bh);
				spin_lock(&journal->j_list_lock);
			}
			locked = 1;
		}
		/* We have to get bh_state lock. Again out of order, sigh. */
		if (!inverted_lock(journal, bh)) {
			jbd_lock_bh_state(bh);
			spin_lock(&journal->j_list_lock);
		}
		/* Someone already cleaned up the buffer? */
		if (!buffer_jbd(bh) || bh2jh(bh) != jh
			|| jh->b_transaction != commit_transaction
			|| jh->b_jlist != BJ_SyncData) {
			/* 该缓冲区已经由别人写回磁盘了，
			 * 那太幸运了 ^^ */
			jbd_unlock_bh_state(bh);
			if (locked)
				unlock_buffer(bh);
			BUFFER_TRACE(bh, "already cleaned up");
			release_data_buffer(bh);
			continue;
		}
		if (locked && test_clear_buffer_dirty(bh)) {
			/* 如果该缓冲区仍是脏的，则需要写回磁盘 */
			BUFFER_TRACE(bh, "needs writeout, adding to array");

			/* 在数组中记录该缓冲区 */
			wbuf[bufs++] = bh;

			/* 将缓冲区移动到BJ_Locked队列上 */
			__journal_file_buffer(jh, commit_transaction,
						BJ_Locked);
			jbd_unlock_bh_state(bh);
			if (bufs == journal->j_wbufsize) {
				/* 如果缓冲区个数已累积到jouranl一次写操作允许的最大值，
				 * 则提交写操作*/
				spin_unlock(&journal->j_list_lock);
				trace_jbd_do_submit_data(journal,
						     commit_transaction);
				journal_do_submit_data(wbuf, bufs, write_op);
				bufs = 0;
				goto write_out_data;
			}
		} else if (!locked && buffer_locked(bh)) {
			__journal_file_buffer(jh, commit_transaction,
						BJ_Locked);
			jbd_unlock_bh_state(bh);
			put_bh(bh);
		} else {
			/* 该缓冲区已经写回磁盘了 */
			BUFFER_TRACE(bh, "writeout complete: unfile");
			if (unlikely(!buffer_uptodate(bh)))
				err = -EIO;
			/* 从本transaction中删除即可 */
			__journal_unfile_buffer(jh);

			jbd_unlock_bh_state(bh);
			if (locked)
				unlock_buffer(bh);
			journal_remove_journal_head(bh);
			/* One for our safety reference, other for
			 * journal_remove_journal_head() */
			put_bh(bh);
			release_data_buffer(bh);
		}

		if (need_resched() || spin_needbreak(&journal->j_list_lock)) {
			spin_unlock(&journal->j_list_lock);
			goto write_out_data;
		}
	}
	spin_unlock(&journal->j_list_lock);
	trace_jbd_do_submit_data(journal, commit_transaction);
	journal_do_submit_data(wbuf, bufs, write_op);

	return err;
}

/*
 * journal_commit_transaction
 *
 * The primary function for committing a transaction to the log.  This
 * function is called by the journal thread to begin a complete commit.
 */
void journal_commit_transaction(journal_t *journal)
{
	transaction_t *commit_transaction;
	struct journal_head *jh, *new_jh, *descriptor;
	struct buffer_head **wbuf = journal->j_wbuf;
	int bufs;
	int flags;
	int err;
	unsigned int blocknr;
	ktime_t start_time;
	u64 commit_time;
	char *tagp = NULL;
	journal_header_t *header;
	journal_block_tag_t *tag = NULL;
	int space_left = 0;
	int first_tag = 0;
	int tag_flag;
	int i;
	int write_op = WRITE_SYNC_PLUG;

	/*
	 * First job: lock down the current transaction and wait for
	 * all outstanding updates to complete.
	 */
	/************************* 事务提交阶段 零 **************************
	 * 1.锁住正在运行的事务，等待该事务所有handle退出 (transaction_s->t_updates == 0)
	 * 2.处理BJ_Reserved队列(transaction_s->t_reserved_list) [直接丢弃]
	 * 3.处理checkpoint队列(transaction_s->t_checkpoint_list)
	 */


#ifdef COMMIT_STATS
	spin_lock(&journal->j_list_lock);
	summarise_journal_usage(journal);
	spin_unlock(&journal->j_list_lock);
#endif

	/* Do we need to erase the effects of a prior journal_flush? */
	if (journal->j_flags & JFS_FLUSHED) {
		jbd_debug(3, "super block updated\n");
		journal_update_superblock(journal, 1); /* 更新日志超级块 */
	} else {
		jbd_debug(3, "superblock not updated\n");
	}

	J_ASSERT(journal->j_running_transaction != NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);

	/* 将当前正在运行的transaction设置为正在提交的transaction，然后进行提交 */
	commit_transaction = journal->j_running_transaction;
	J_ASSERT(commit_transaction->t_state == T_RUNNING);

	trace_jbd_start_commit(journal, commit_transaction);
	jbd_debug(1, "JBD: starting commit of transaction %d\n",
			commit_transaction->t_tid);

	spin_lock(&journal->j_state_lock);

	/* 将transaction的状态设置为T_LOCKED，表示不能再向其中加入新的原子操作了。*/
	commit_transaction->t_state = T_LOCKED;

	trace_jbd_commit_locking(journal, commit_transaction);
	spin_lock(&commit_transaction->t_handle_lock);
	while (commit_transaction->t_updates) {
		/* t_updates不为0时，表示仍有handle在修改此transaction
		 * 故需要等所有的handle结束才能commit
		 */
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (commit_transaction->t_updates) {
			spin_unlock(&commit_transaction->t_handle_lock);
			spin_unlock(&journal->j_state_lock);
			schedule();
			spin_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);
	/* 现在该事务的所有handle都结束了 */

	J_ASSERT (commit_transaction->t_outstanding_credits <=
			journal->j_max_transaction_buffers);

	/*
	 * First thing we are allowed to do is to discard any remaining
	 * BJ_Reserved buffers.  Note, it is _not_ permissible to assume
	 * that there are no such buffers: if a large filesystem
	 * operation like a truncate needs to split itself over multiple
	 * transactions, then it may try to do a journal_restart() while
	 * there are still BJ_Reserved buffers outstanding.  These must
	 * be released cleanly from the current transaction.
	 *
	 * In this case, the filesystem must still reserve write access
	 * again before modifying the buffer in the new transaction, but
	 * we do not require it to remember exactly which old buffers it
	 * has reserved.  This is consistent with the existing behaviour
	 * that multiple journal_get_write_access() calls to the same
	 * buffer are perfectly permissable.
	 */
	while (commit_transaction->t_reserved_list) {
		/* t_reserved_list队列上的缓冲区是本transaction已管理的、但是未修改的缓冲区。
		 * 既然未修改，则不必提交。
		 */
		jh = commit_transaction->t_reserved_list;
		JBUFFER_TRACE(jh, "reserved, unused: refile");
		/*
		 * A journal_get_undo_access()+journal_release_buffer() may
		 * leave undo-committed data.
		 */
		if (jh->b_committed_data) {
			struct buffer_head *bh = jh2bh(jh);

			jbd_lock_bh_state(bh);
			jbd_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			jbd_unlock_bh_state(bh);
		}

		/* 将该jh从本transaction中移除 */
		journal_refile_buffer(journal, jh);
	}

	/*
	 * Now try to drop any written-back buffers from the journal's
	 * checkpoint lists.  We do this *before* commit because it potentially
	 * frees some memory
	 */
	spin_lock(&journal->j_list_lock);

	/* 处理checkpoint队列
	 * 先遍历journal中所有已提交的事务，依次处理其中的checkpoint队列 */
	__journal_clean_checkpoint_list(journal);
	spin_unlock(&journal->j_list_lock);


	/************************* 事务提交阶段 一 **************************
	 * 1.切换正在使用的revoke哈希表(journal_s->j_revoke)
	 * 2.设置正在提交的事务 (journal_s->j_committing_transaction)
	 */ 
	jbd_debug (3, "JBD: commit phase 1\n");

	/*
	 * Switch to a new revoke table.
	 */
	/* 切换一下revoke hash table。
	 * 这样就不会发生该表一边被提交，一边被修改的情况。*/
	journal_switch_revoke_table(journal);

	trace_jbd_commit_flushing(journal, commit_transaction);

	/* 将transaction的状态设置为T_FLUSH */
	commit_transaction->t_state = T_FLUSH;
	journal->j_committing_transaction = commit_transaction; /* 将该事务设置为正在提交的事务 */
	/* 设置运行的事务为空，之后再加入handle会分配一个新的事务 */
	journal->j_running_transaction = NULL; 			

	start_time = ktime_get();
	commit_transaction->t_log_start = journal->j_head; /* 设置该事务在log中开始的块 */
	wake_up(&journal->j_wait_transaction_locked);
	spin_unlock(&journal->j_state_lock);

	
	/************************* 事务提交阶段 二 **************************
	 * 1.提交数据块缓冲区
	 * 	从BJ_SyncData队列(transaction_s->t_sync_datalist)移动到
	 * 	BJ_Locked队列（transaction_s->t_locked_list)
	 * 2.等待数据块缓冲区写完成
	 * 3.写取消块(journal_s->j_revoke_table[0 || 1]
	 */
	jbd_debug (3, "JBD: commit phase 2\n");

	/*
	 * Now start flushing things to disk, in the order they appear
	 * on the transaction lists.  Data blocks go first.
	 */
	/* 将与本transaction相关联的数据块缓冲区先写回磁盘，ordered模式就是这样实现的。
	 * 这些数据块缓冲区原来在BJ_SyncData队列上，
	 * journal_submit_data_buffers()会将它们移动到BJ_Locked队列上
	 */
	err = journal_submit_data_buffers(journal, commit_transaction,
					  write_op);

	/*
	 * Wait for all previously submitted IO to complete.
	 */
	/* 等待数据块缓冲区写入完成 */
	spin_lock(&journal->j_list_lock);
	while (commit_transaction->t_locked_list) {
		struct buffer_head *bh;

		jh = commit_transaction->t_locked_list->b_tprev;
		bh = jh2bh(jh);
		get_bh(bh);
		if (buffer_locked(bh)) { /* 说明io已经提交，但是没完成 */
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh); /* 等待写回完成 */
			spin_lock(&journal->j_list_lock);
		}
		if (unlikely(!buffer_uptodate(bh))) {
			if (!trylock_page(bh->b_page)) {
				spin_unlock(&journal->j_list_lock);
				lock_page(bh->b_page);
				spin_lock(&journal->j_list_lock);
			}
			if (bh->b_page->mapping)
				set_bit(AS_EIO, &bh->b_page->mapping->flags);

			unlock_page(bh->b_page);
			SetPageError(bh->b_page);
			err = -EIO;
		}
		if (!inverted_lock(journal, bh)) {
			put_bh(bh);
			spin_lock(&journal->j_list_lock);
			continue;
		}
		if (buffer_jbd(bh) && bh2jh(bh) == jh &&
		    jh->b_transaction == commit_transaction &&
		    jh->b_jlist == BJ_Locked) {
			/* 将jh从transaction中删除 */
			__journal_unfile_buffer(jh);
			jbd_unlock_bh_state(bh);
			journal_remove_journal_head(bh);
			put_bh(bh);
		} else {
			jbd_unlock_bh_state(bh);
		}
		release_data_buffer(bh);
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	if (err) {
		char b[BDEVNAME_SIZE];

		printk(KERN_WARNING
			"JBD: Detected IO errors while flushing file data "
			"on %s\n", bdevname(journal->j_fs_dev, b));
		if (journal->j_flags & JFS_ABORT_ON_SYNCDATA_ERR)
			journal_abort(journal, err);
		err = 0;
	}

	/* 将revoke hash table中的记录写到日志中,
	 * 即写入取消块。*/
	journal_write_revoke_records(journal, commit_transaction, write_op);

	/*
	 * If we found any dirty or locked buffers, then we should have
	 * looped back up to the write_out_data label.  If there weren't
	 * any then journal_clean_data_list should have wiped the list
	 * clean by now, so check that it is in fact empty.
	 */
	/* 现在要确保该事务的数据缓冲区队列为空，即数据缓冲区都写回磁盘 */
	J_ASSERT (commit_transaction->t_sync_datalist == NULL);



	/************************* 事务提交阶段 三 **************************
	 * 1.构造描述符块
	 * 2.提交元数据块。
	 * 	将BJ_Metadata队列(transaction_s->t_buffers)
	 *   	移到BJ_Shadow队列(transaction_s->t_shadow_list),
	 *  	同时复制一份到BJ_IO队列(transaction_s->t_iobuf_list)
	 */
	jbd_debug (3, "JBD: commit phase 3\n");

	/*
	 * Way to go: we have now written out all of the data for a
	 * transaction!  Now comes the tricky part: we need to write out
	 * metadata.  Loop over the transaction's entire buffer list:
	 */
	spin_lock(&journal->j_state_lock);
	/* 将transaction的状态设置为T_COMMIT */
	commit_transaction->t_state = T_COMMIT;
	spin_unlock(&journal->j_state_lock);

	trace_jbd_commit_logging(journal, commit_transaction);
	J_ASSERT(commit_transaction->t_nr_buffers <=
		 commit_transaction->t_outstanding_credits);

	descriptor = NULL;
	bufs = 0;

	/* 将BJ_Metadata 队列(即t_buffers)中的元数据缓冲区写到日志中
	 * 这里只是启动所有缓冲区的写操作，第四阶段会等待写操作完成
	 */
	while (commit_transaction->t_buffers) { /* 遍历t_buffers队列的每个缓冲区 */

		/* Find the next buffer to be journaled... */

		jh = commit_transaction->t_buffers;

		/* If we're in abort mode, we just un-journal the buffer and
		   release it. */

		if (is_journal_aborted(journal)) { /* abort, 不提交日志,释放缓冲区 */
			clear_buffer_jbddirty(jh2bh(jh));
			JBUFFER_TRACE(jh, "journal is aborting: refile");
			journal_refile_buffer(journal, jh);
			/* If that was the last one, we need to clean up
			 * any descriptor buffers which may have been
			 * already allocated, even if we are now
			 * aborting. */
			if (!commit_transaction->t_buffers)
				goto start_journal_io;
			continue;
		}

		/* Make sure we have a descriptor block in which to
		   record the metadata buffer. */
		/* 元数据块缓冲区写入日志的格式是：描述符块、数据块、提交块
		 * 这里的descriptor 表示一个描述符块
		 */
		if (!descriptor) { /* 如果没有描述块，则创建 */
			struct buffer_head *bh;

			J_ASSERT (bufs == 0);

			jbd_debug(4, "JBD: get descriptor\n");

			/* 从日志空间新分配一个块，用作描述符块 */
			descriptor = journal_get_descriptor_buffer(journal);
			if (!descriptor) {
				journal_abort(journal, -EIO);
				continue;
			}

			bh = jh2bh(descriptor);
			jbd_debug(4, "JBD: got buffer %llu (%p)\n",
				(unsigned long long)bh->b_blocknr, bh->b_data);

			/* 设置描述符块 */
			header = (journal_header_t *)&bh->b_data[0];
			header->h_magic     = cpu_to_be32(JFS_MAGIC_NUMBER);
			header->h_blocktype = cpu_to_be32(JFS_DESCRIPTOR_BLOCK);
			header->h_sequence  = cpu_to_be32(commit_transaction->t_tid);

			/* tagp用于指示新的journal_block_tag_t的起点 */
			tagp = &bh->b_data[sizeof(journal_header_t)];
			space_left = bh->b_size - sizeof(journal_header_t);
			first_tag = 1;
			set_buffer_jwrite(bh);
			set_buffer_dirty(bh);
			/* wbuf[]数组记录要写到日志的所有缓冲区 */
			wbuf[bufs++] = bh;

			/* Record it so that we can wait for IO
                           completion later */
			BUFFER_TRACE(bh, "ph3: file as descriptor");
			/* 将描述符块的缓冲区加入BJ_LogCtl队列，下面会写出到日志 */
			journal_file_buffer(descriptor, commit_transaction,
					BJ_LogCtl);
		}

		/* Where is the buffer to be written? */
		/* 计算日志中下一个空间块的块号，保存在blocknr中 */
		err = journal_next_log_block(journal, &blocknr);
		/* If the block mapping failed, just abandon the buffer
		   and repeat this loop: we'll fall into the
		   refile-on-abort condition above. */
		if (err) {
			journal_abort(journal, err);
			continue;
		}

		/*
		 * start_this_handle() uses t_outstanding_credits to determine
		 * the free space in the log, but this counter is changed
		 * by journal_next_log_block() also.
		 */
		commit_transaction->t_outstanding_credits--;

		/* Bump b_count to prevent truncate from stumbling over
                   the shadowed buffer!  @@@ This can go if we ever get
                   rid of the BJ_IO/BJ_Shadow pairing of buffers. */
		atomic_inc(&jh2bh(jh)->b_count);

		/* Make a temporary IO buffer with which to write it out
                   (this will requeue both the metadata buffer and the
                   temporary IO buffer). new_bh goes on BJ_IO*/

		set_bit(BH_JWrite, &jh2bh(jh)->b_state);
		/*
		 * akpm: journal_write_metadata_buffer() sets
		 * new_bh->b_transaction to commit_transaction.
		 * We need to clean this up before we release new_bh
		 * (which is of type BJ_IO)
		 */
		JBUFFER_TRACE(jh, "ph3: write metadata");

		/* journal_write_metadata_buffer()函数从字面意思上看是写一个元数据缓冲区，
		 * 但是实际上它并未完成真正的写操作。
		 * 它主要的作用是根据已存在的元数据块缓冲区（jh对应的那个）
		 * 创建一个新的缓冲区（new_jh对应的那个），供jbd写入到日志时使用。
		 * jh此时会从BJ_Metadata队列(t_buffers)上移动到BJ_Shadow(t_shadow_list)队列上，
		 * 而new_jh则会链入到BJ_IO(t_iobuf_list)队列上。
		 * journal_write_metadata_buffer()函数也会处理转义问题。
		 */
		flags = journal_write_metadata_buffer(commit_transaction,
						      jh, &new_jh, blocknr);
		set_bit(BH_JWrite, &jh2bh(new_jh)->b_state);

		/* 记录下来，后面一起写出 */
		wbuf[bufs++] = jh2bh(new_jh);

		/* Record the new block's tag in the current descriptor
                   buffer */

		/* 将刚写出的缓冲区信息记录在描述符块的索引项中 */
		tag_flag = 0;
		if (flags & 1) 	/* 该块被转义了 */
			tag_flag |= JFS_FLAG_ESCAPE;
		if (!first_tag) /* 不是第一个索引项，设置于前一项相同的UUID */
			tag_flag |= JFS_FLAG_SAME_UUID;

		tag = (journal_block_tag_t *) tagp;
		/* 记录块号和标志 */
		tag->t_blocknr = cpu_to_be32(jh2bh(jh)->b_blocknr);
		tag->t_flags = cpu_to_be32(tag_flag);

		tagp += sizeof(journal_block_tag_t);
		space_left -= sizeof(journal_block_tag_t);

		if (first_tag) { /* 本描述符块的第一个journal_block_tag_t会记录一个UUID */
			memcpy (tagp, journal->j_uuid, 16);
			tagp += 16;
			space_left -= 16;
			first_tag = 0;
		}

		/* If there's no more to do, or if the descriptor is full,
		   let the IO rip! */
		/* 如果达到了journal一次允许写出的缓冲区个数，
		 * 或者BJ_Metadata 队列已经为空，
		 * 或者描述符块已被journal_block_tag_t记录填满了
		 * 则需进行提交
		 */
		if (bufs == journal->j_wbufsize ||
		    commit_transaction->t_buffers == NULL ||
		    space_left < sizeof(journal_block_tag_t) + 16) {

			jbd_debug(4, "JBD: Submit %d IOs\n", bufs);

			/* Write an end-of-descriptor marker before
                           submitting the IOs.  "tag" still points to
                           the last tag we set up. */
			/* 描述块的最后一个索引项要有JFS_FLAG_LAST_TAG标志 */
			tag->t_flags |= cpu_to_be32(JFS_FLAG_LAST_TAG);

start_journal_io:
			/* 启动写操作 */
			for (i = 0; i < bufs; i++) {
				struct buffer_head *bh = wbuf[i];
				lock_buffer(bh);
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;
				submit_bh(write_op, bh);
			}
			cond_resched();

			/* Force a new descriptor to be generated next
                           time round the loop. */
			/* 如果描述符块已被journal_block_tag_t记录填满了，则重新分配一个 */
			descriptor = NULL;
			bufs = 0;
		}
	}

	/* Lo and behold: we have just managed to send a transaction to
           the log.  Before we can commit it, wait for the IO so far to
           complete.  Control buffers being written are on the
           transaction's t_log_list queue, and metadata buffers are on
           the t_iobuf_list queue.

	   Wait for the buffers in reverse order.  That way we are
	   less likely to be woken up until all IOs have completed, and
	   so we incur less scheduling load.
	*/


	
	/************************* 事务提交阶段 四 **************************
	 * 等待元数据块提交完成。
	 * 	提交完成后删除BJ_IO队列(transaction_s->t_iobuf_list),
	 *	同时将对应的BJ_Shadow队列(transaction_s->t_shadow_list)移动到
	 *	BJ_Forget队列(transaction_s->t_forget)
	 */
	jbd_debug(3, "JBD: commit phase 4\n");

	/*
	 * akpm: these are BJ_IO, and j_list_lock is not needed.
	 * See __journal_try_to_free_buffer.
	 */
wait_for_iobuf:
	/* 等待每个元数据块缓冲区写入日志 */
	while (commit_transaction->t_iobuf_list != NULL) {
		struct buffer_head *bh;

		jh = commit_transaction->t_iobuf_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) { /* 说明io已经提交，但是没完成 */
			wait_on_buffer(bh); /* 等待完成 */
			goto wait_for_iobuf;
		}
		if (cond_resched())
			goto wait_for_iobuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		clear_buffer_jwrite(bh);

		JBUFFER_TRACE(jh, "ph4: unfile after journal write");
		/* 将jh从对应事务的相应队列中删除 */
		journal_unfile_buffer(journal, jh);

		/*
		 * ->t_iobuf_list should contain only dummy buffer_heads
		 * which were created by journal_write_metadata_buffer().
		 */
		BUFFER_TRACE(bh, "dumping temporary bh");
		journal_put_journal_head(jh);
		__brelse(bh);
		J_ASSERT_BH(bh, atomic_read(&bh->b_count) == 0);
		free_buffer_head(bh);

		/* We also have to unlock and free the corresponding
                   shadowed buffer */
		/* BJ_IO 队列上的缓冲区与BJ_Shadow队列上的缓冲区是一一对应的。
		 * 每处理完一个BJ_IO队列上的缓冲区，都会将其从transaction中删除，
		 * 并且要将在BJ_Shadow队列上对应的缓冲区移到BJ_Forget队列上。
		 * (后面checkpoint 还要处理BJ_Forget队列)
		 */
		jh = commit_transaction->t_shadow_list->b_tprev;
		bh = jh2bh(jh);
		clear_bit(BH_JWrite, &bh->b_state);
		J_ASSERT_BH(bh, buffer_jbddirty(bh));

		/* The metadata is now released for reuse, but we need
                   to remember it against this transaction so that when
                   we finally commit, we can do any checkpointing
                   required. */
		JBUFFER_TRACE(jh, "file as BJ_Forget");
		/* 将jh从BJ_Shadow队列移到BG_Forget队列 */
		journal_file_buffer(jh, commit_transaction, BJ_Forget);
		/*
		 * Wake up any transactions which were waiting for this
		 * IO to complete. The barrier must be here so that changes
		 * by journal_file_buffer() take effect before wake_up_bit()
		 * does the waitqueue check.
		 */
		smp_mb();
		wake_up_bit(&bh->b_state, BH_Unshadow);
		JBUFFER_TRACE(jh, "brelse shadowed buffer");
		__brelse(bh);
	}

	J_ASSERT (commit_transaction->t_shadow_list == NULL);


	/************************* 事务提交阶段 五 **************************
	 * 等待所有控制块写入完成。
	 * 	包括描述符块和取消块, 在BJ_LogCtl队列(transaction_s->t_log_list)
	 */
	jbd_debug(3, "JBD: commit phase 5\n");

	/* Here we wait for the revoke record and descriptor record buffers */
 wait_for_ctlbuf:
 	/* 等待取消块和描述符块写入日志。
	 * 取消块和描述符块都可视为jbd的控制块，都在BJ_LogCtl队列上。
	 */
	while (commit_transaction->t_log_list != NULL) {
		/* 等待每一个控制块都写入日志 */
		struct buffer_head *bh;

		jh = commit_transaction->t_log_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) { /* 已提交，未写完成 */
			wait_on_buffer(bh); /* 等待写回 */
			goto wait_for_ctlbuf;
		}
		if (cond_resched())
			goto wait_for_ctlbuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		BUFFER_TRACE(bh, "ph5: control buffer writeout done: unfile");
		clear_buffer_jwrite(bh);
		/* 控制块已经写到日志中了，则可以从transaction中删除了 */
		journal_unfile_buffer(journal, jh);
		journal_put_journal_head(jh);
		__brelse(bh);		/* One for getblk */
		/* AKPM: bforget here */
	}

	if (err)
		journal_abort(journal, err);


	/************************* 事务提交阶段 六 **************************
	 * 写提交块
	 */
	jbd_debug(3, "JBD: commit phase 6\n");

	/* 描述符块和数据块都写到日志中了，
	 * 现在写一个提交块。
	 */
	if (journal_write_commit_record(journal, commit_transaction))
		err = -EIO;

	if (err)
		journal_abort(journal, err);

	/* End of a transaction!  Finally, we can do checkpoint
           processing: any buffers committed as a result of this
           transaction can be removed from any checkpoint list it was on
           before. */


	/************************* 事务提交阶段 七 **************************
	 * 处理BJ_Forget队列(transaction_s->t_forget)
	 * 	BJ_Forget队列中的缓冲区如果为dirty状态就加入transaction_s->t_checkpoint_list队列
	 * 	如果为update状态就直接从BJ_Forget上删除
	 */
	jbd_debug(3, "JBD: commit phase 7\n");
	
	/* 确保下列队列都为空了 */
	J_ASSERT(commit_transaction->t_sync_datalist == NULL);
	J_ASSERT(commit_transaction->t_buffers == NULL);
	J_ASSERT(commit_transaction->t_checkpoint_list == NULL);
	J_ASSERT(commit_transaction->t_iobuf_list == NULL);
	J_ASSERT(commit_transaction->t_shadow_list == NULL);
	J_ASSERT(commit_transaction->t_log_list == NULL);

restart_loop:
	/*
	 * As there are other places (journal_unmap_buffer()) adding buffers
	 * to this list we have to be careful and hold the j_list_lock.
	 */
	spin_lock(&journal->j_list_lock);
	while (commit_transaction->t_forget) {
		/* 这里实现checkpoint机制的地方。
		 * 此时，对元数据块缓冲区而言，
		 * 或者它已被内核按照原有的方式写回到磁盘的原始位置(update状态)，
		 * 	那么直接从transaction中删除即可；
		 * 或者未被内核写回到磁盘的原始位置(dirty状态)，
		 * 	这样我们就要把它加入到本transaction的checkpoint队列上，
		 */
		transaction_t *cp_transaction;
		struct buffer_head *bh;

		jh = commit_transaction->t_forget;
		spin_unlock(&journal->j_list_lock);
		bh = jh2bh(jh);
		jbd_lock_bh_state(bh);
		J_ASSERT_JH(jh,	jh->b_transaction == commit_transaction ||
			jh->b_transaction == journal->j_running_transaction);

		/*
		 * If there is undo-protected committed data against
		 * this buffer, then we can remove it now.  If it is a
		 * buffer needing such protection, the old frozen_data
		 * field now points to a committed version of the
		 * buffer, so rotate that field to the new committed
		 * data.
		 *
		 * Otherwise, we can just throw away the frozen data now.
		 */
		/* 释放掉jh的b_committed_data或b_frozen_data */
		if (jh->b_committed_data) {
			jbd_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			if (jh->b_frozen_data) {
				jh->b_committed_data = jh->b_frozen_data;
				jh->b_frozen_data = NULL;
			}
		} else if (jh->b_frozen_data) {
			jbd_free(jh->b_frozen_data, bh->b_size);
			jh->b_frozen_data = NULL;
		}

		spin_lock(&journal->j_list_lock);
		cp_transaction = jh->b_cp_transaction;
		if (cp_transaction) {
			/* 如果该jh已经在旧的transaction的checkpoint队列上了，
			 * 则从旧的transaction的checkpoint队列上删除，
			 * 因为我们会把它加入到本transaction的checkpoint队列上
			 */
			JBUFFER_TRACE(jh, "remove from old cp transaction");
			__journal_remove_checkpoint(jh);
		}

		/* Only re-checkpoint the buffer_head if it is marked
		 * dirty.  If the buffer was added to the BJ_Forget list
		 * by journal_forget, it may no longer be dirty and
		 * there's no point in keeping a checkpoint record for
		 * it. */

		/* A buffer which has been freed while still being
		 * journaled by a previous transaction may end up still
		 * being dirty here, but we want to avoid writing back
		 * that buffer in the future now that the last use has
		 * been committed.  That's not only a performance gain,
		 * it also stops aliasing problems if the buffer is left
		 * behind for writeback and gets reallocated for another
		 * use in a different page. */
		if (buffer_freed(bh)) {
			clear_buffer_freed(bh);
			clear_buffer_jbddirty(bh);
		}

		if (buffer_jbddirty(bh)) { /* 如果该缓冲区仍为脏 */
			JBUFFER_TRACE(jh, "add to new checkpointing trans");
			/* 加入到本transaction的checkpoint队列上 */
			__journal_insert_checkpoint(jh, commit_transaction);
			if (is_journal_aborted(journal))
				clear_buffer_jbddirty(bh);
			JBUFFER_TRACE(jh, "refile for checkpoint writeback");
			/*
			 * 该jh除了在本transaction的checkpoint队列上之外，
			 * 不需要在其他队列上了。
			 * 从transaction的队列上移除
			 */
			__journal_refile_buffer(jh);
			jbd_unlock_bh_state(bh);
		} else { /* 该缓冲区已处于update状态，直接从transaction中删除即可。*/
			J_ASSERT_BH(bh, !buffer_dirty(bh));
			/* The buffer on BJ_Forget list and not jbddirty means
			 * it has been freed by this transaction and hence it
			 * could not have been reallocated until this
			 * transaction has committed. *BUT* it could be
			 * reallocated once we have written all the data to
			 * disk and before we process the buffer on BJ_Forget
			 * list. */
			JBUFFER_TRACE(jh, "refile or unfile freed buffer");
			__journal_refile_buffer(jh);
			if (!jh->b_transaction) {
				jbd_unlock_bh_state(bh);
				 /* needs a brelse */
				journal_remove_journal_head(bh);
				release_buffer_page(bh);
			} else
				jbd_unlock_bh_state(bh);
		}
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);
	/*
	 * This is a bit sleazy.  We use j_list_lock to protect transition
	 * of a transaction into T_FINISHED state and calling
	 * __journal_drop_transaction(). Otherwise we could race with
	 * other checkpointing code processing the transaction...
	 */
	spin_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	/*
	 * Now recheck if some buffers did not get attached to the transaction
	 * while the lock was dropped...
	 */
	/* 如果因为加锁过程中BJ_Forget队列上又有缓冲区了 */
	if (commit_transaction->t_forget) {
		spin_unlock(&journal->j_list_lock);
		spin_unlock(&journal->j_state_lock);
		goto restart_loop;
	}

	/* Done with this transaction! */


	/************************* 事务提交阶段 八 **************************
	 * 将正在提交的事务加入journal_s->j_checkpoint_transactions队列
	 */
	jbd_debug(3, "JBD: commit phase 8\n");

	J_ASSERT(commit_transaction->t_state == T_COMMIT);

	/* 将transaction的状态设置为T_FINISHED */
	commit_transaction->t_state = T_FINISHED;
	J_ASSERT(commit_transaction == journal->j_committing_transaction);
	/* 将最近已经提交的事务设置为本事务 */
	journal->j_commit_sequence = commit_transaction->t_tid;
	journal->j_committing_transaction = NULL; /* 正在提交的事务设置为空 */
	commit_time = ktime_to_ns(ktime_sub(ktime_get(), start_time)); /* 计算提交的时间 */

	/*
	 * weight the commit time higher than the average time so we don't
	 * react too strongly to vast changes in commit time
	 */
	/* 计算提交事务的平均时间 */
	if (likely(journal->j_average_commit_time)) 
		journal->j_average_commit_time = (commit_time*3 +
				journal->j_average_commit_time) / 4;
	else
		journal->j_average_commit_time = commit_time;

	spin_unlock(&journal->j_state_lock);

	if (commit_transaction->t_checkpoint_list == NULL &&
	    commit_transaction->t_checkpoint_io_list == NULL) {
		/* 本事务的checkpoint已经为空，则本事务可从内存中直接删除了 */
		__journal_drop_transaction(journal, commit_transaction);
	} else { /* 将本事务插入journal的j_checkpoint_transactions队列 */
		if (journal->j_checkpoint_transactions == NULL) {
			journal->j_checkpoint_transactions = commit_transaction;
			commit_transaction->t_cpnext = commit_transaction;
			commit_transaction->t_cpprev = commit_transaction;
		} else {
			commit_transaction->t_cpnext =
				journal->j_checkpoint_transactions;
			commit_transaction->t_cpprev =
				commit_transaction->t_cpnext->t_cpprev;
			commit_transaction->t_cpnext->t_cpprev =
				commit_transaction;
			commit_transaction->t_cpprev->t_cpnext =
				commit_transaction;
		}
	}
	spin_unlock(&journal->j_list_lock);

	trace_jbd_end_commit(journal, commit_transaction);
	jbd_debug(1, "JBD: commit %d complete, head %d\n",
		  journal->j_commit_sequence, journal->j_tail_sequence);

	wake_up(&journal->j_wait_done_commit);
}
