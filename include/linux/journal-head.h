/*
 * include/linux/journal-head.h
 *
 * buffer_head fields for JBD
 *
 * 27 May 2001 Andrew Morton
 *	Created - pulled out of fs.h
 */

#ifndef JOURNAL_HEAD_H_INCLUDED
#define JOURNAL_HEAD_H_INCLUDED

typedef unsigned int		tid_t;		/* Unique transaction ID */
typedef struct transaction_s	transaction_t;	/* Compound transaction type */


struct buffer_head;

struct journal_head { /* journal_head 对应一个buffer_head,日志通过journal_head对缓冲区进行管理 */
	/*
	 * Points back to our buffer_head. [jbd_lock_bh_journal_head()]
	 */
	struct buffer_head *b_bh;

	/*
	 * Reference count - see description in journal.c
	 * [jbd_lock_bh_journal_head()]
	 */
	int b_jcount;

	/*
	 * Journalling list for this buffer [jbd_lock_bh_state()]
	 */
	unsigned b_jlist; 	/* 本journal_head在transaction_t的哪个链表上 */

	/*
	 * This flag signals the buffer has been modified by
	 * the currently running transaction
	 * [jbd_lock_bh_state()]
	 */
	unsigned b_modified; /* 标志该缓冲区是否已被当前正在运行的transaction修改过 */

	/*
	 * Copy of the buffer data frozen for writing to the log.
	 * [jbd_lock_bh_state()]
	 */
	char *b_frozen_data; /* 当jbd遇到需要转义的块时，
				将buffer_head指向的缓冲区数据拷贝出来，冻结起来，供写入日志使用 */

	/*
	 * Pointer to a saved copy of the buffer containing no uncommitted
	 * deallocation references, so that allocations can avoid overwriting
	 * uncommitted deletes. [jbd_lock_bh_state()]
	 */
	char *b_committed_data;		/* 目的是防止重新写未提交的删除操作
					 * 含有未提交的删除信息的元数据块（磁盘块位图）的一份拷贝，
					 * 因此随后的分配操作可以避免覆盖未提交的删除信息。
					 * 也就是说随后的分配操作使用的时b_committed_data 中的数据，
					 * 因此不会影响到写入日志中的数据。
					 */

	/*
	 * Pointer to the compound transaction which owns this buffer's
	 * metadata: either the running transaction or the committing
	 * transaction (if there is one).  Only applies to buffers on a
	 * transaction's data or metadata journaling list.
	 * [j_list_lock] [jbd_lock_bh_state()]
	 */
	transaction_t *b_transaction; 	/* 指向所属的transaction */

	/*
	 * Pointer to the running compound transaction which is currently
	 * modifying the buffer's metadata, if there was already a transaction
	 * committing it when the new transaction touched it.
	 * [t_list_lock] [jbd_lock_bh_state()]
	 */
	transaction_t *b_next_transaction; /* 当有一个transaction正在提交本缓冲区，
					    * 但是另一个transaction要修改本元数据缓冲区的数据，
					    * 该指针就指向第二个缓冲区。
					    */

	/*
	 * Doubly-linked list of buffers on a transaction's data, metadata or
	 * forget queue. [t_list_lock] [jbd_lock_bh_state()]
	 */
	struct journal_head *b_tnext, *b_tprev;

	/*
	 * Pointer to the compound transaction against which this buffer
	 * is checkpointed.  Only dirty buffers can be checkpointed.
	 * [j_list_lock]
	 */
	transaction_t *b_cp_transaction; /* 指向checkpoint本缓冲区的transaction。
					只有脏的缓冲区可以被checkpointed*/

	/*
	 * Doubly-linked list of buffers still remaining to be flushed
	 * before an old transaction can be checkpointed.
	 * [j_list_lock]
	 */
	struct journal_head *b_cpnext, *b_cpprev; /* 在旧的transaction_t被checkpointed之前
							必须被刷新的缓冲区双向链表。 */

	/* Trigger type */
	struct jbd2_buffer_trigger_type *b_triggers;

	/* Trigger type for the committing transaction's frozen data */
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

#endif		/* JOURNAL_HEAD_H_INCLUDED */
