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

struct journal_head { /* journal_head ��Ӧһ��buffer_head,��־ͨ��journal_head�Ի��������й��� */
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
	unsigned b_jlist; 	/* ��journal_head��transaction_t���ĸ������� */

	/*
	 * This flag signals the buffer has been modified by
	 * the currently running transaction
	 * [jbd_lock_bh_state()]
	 */
	unsigned b_modified; /* ��־�û������Ƿ��ѱ���ǰ�������е�transaction�޸Ĺ� */

	/*
	 * Copy of the buffer data frozen for writing to the log.
	 * [jbd_lock_bh_state()]
	 */
	char *b_frozen_data; /* ��jbd������Ҫת��Ŀ�ʱ��
				��buffer_headָ��Ļ��������ݿ���������������������д����־ʹ�� */

	/*
	 * Pointer to a saved copy of the buffer containing no uncommitted
	 * deallocation references, so that allocations can avoid overwriting
	 * uncommitted deletes. [jbd_lock_bh_state()]
	 */
	char *b_committed_data;		/* Ŀ���Ƿ�ֹ����дδ�ύ��ɾ������
					 * ����δ�ύ��ɾ����Ϣ��Ԫ���ݿ飨���̿�λͼ����һ�ݿ�����
					 * ������ķ���������Ա��⸲��δ�ύ��ɾ����Ϣ��
					 * Ҳ����˵���ķ������ʹ�õ�ʱb_committed_data �е����ݣ�
					 * ��˲���Ӱ�쵽д����־�е����ݡ�
					 */

	/*
	 * Pointer to the compound transaction which owns this buffer's
	 * metadata: either the running transaction or the committing
	 * transaction (if there is one).  Only applies to buffers on a
	 * transaction's data or metadata journaling list.
	 * [j_list_lock] [jbd_lock_bh_state()]
	 */
	transaction_t *b_transaction; 	/* ָ��������transaction */

	/*
	 * Pointer to the running compound transaction which is currently
	 * modifying the buffer's metadata, if there was already a transaction
	 * committing it when the new transaction touched it.
	 * [t_list_lock] [jbd_lock_bh_state()]
	 */
	transaction_t *b_next_transaction; /* ����һ��transaction�����ύ����������
					    * ������һ��transactionҪ�޸ı�Ԫ���ݻ����������ݣ�
					    * ��ָ���ָ��ڶ�����������
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
	transaction_t *b_cp_transaction; /* ָ��checkpoint����������transaction��
					ֻ����Ļ��������Ա�checkpointed*/

	/*
	 * Doubly-linked list of buffers still remaining to be flushed
	 * before an old transaction can be checkpointed.
	 * [j_list_lock]
	 */
	struct journal_head *b_cpnext, *b_cpprev; /* �ھɵ�transaction_t��checkpointed֮ǰ
							���뱻ˢ�µĻ�����˫������ */

	/* Trigger type */
	struct jbd2_buffer_trigger_type *b_triggers;

	/* Trigger type for the committing transaction's frozen data */
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

#endif		/* JOURNAL_HEAD_H_INCLUDED */
