/*
 *  Deadline i/o scheduler.
 *
 *  Copyright (C) 2002 Jens Axboe <axboe@kernel.dk>
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/compiler.h>
#include <linux/rbtree.h>

/*
 * See Documentation/block/deadline-iosched.txt
 */
static const int read_expire = HZ / 2;  /* max time before a read is submitted. *//* ����ʱʱ��0.5S */
static const int write_expire = 5 * HZ; /* ditto for writes, these limits are SOFT! *//* д��ʱʱ��5S */

/* writes_starvedĬ��Ϊ2���������Ϊд����ļ����ߣ�
 * �ں��������ȴ��������starved������ǰ����Ķ�����������
 * ֻ��starved������writes_starved�󣬲Ż�ȥ����д����
 * ��ˣ�����һ��д����������Ѿ�������������Ҳ��һ���ᱻ������Ӧ��
 * ��Ϊ�������batch��û�����꣬��ʹ�����꣬
 * Ҳ����ȵ�starved����writes_starved���л��ᱻ��Ӧ  
 */
static const int writes_starved = 2;    /* max times reads can starve a write */
					/* д����ļ�������������writes_starved���������˶������
					 * ���봦��д���󣬷�ֹд������� */
static const int fifo_batch = 16;       /* # of sequential requests treated as one
				     by the above parameters. For throughput. */
				     	/* һ�������������������� */

struct deadline_data {
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2];	/* ��д����ĺ���������������ʼ���������� */
	struct list_head fifo_list[2]; 	/* ��д������������������Ӧ���������� */

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2]; 	/* ��һ����(д)���󣬵�ȷ��һ����������ʱ��
					 * ͨ����ָ��ֱ�ӻ�ȡ��һ������ */
	unsigned int batching;		/* number of sequential requests made */
					/* ��������ĵ�ǰֵ */
					/* ���ڼ�¼��ǰ�����ύ��request��Ŀ����batching < fifo_batch��
					 * �����Լ������������ύ  */
	sector_t last_sector;		/* head position */
					/* �����rq��ĩβ������ */
	unsigned int starved;		/* times reads have starved writes */
					/* ��ʶ�ŵ�ǰ�ǵ�starved���������� */
					/* ���starved����writes_starved������Ҫ�ύдrequest���Ӷ�����д���� */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2]; 		/* ��д���������ֵ */
	int fifo_batch; 		/* ��������������� */
	int writes_starved; 		/* д����Ķ����ߣ�
					 * ������writes_starved��������󣬱��봫��д���� */
	int front_merges; 		/* �Ƿ�ʹ��front merge�ļ�� 
					 * ��1Ϊ������ǰ�ϲ�, ��������request��ǰ�����bio */
};

static void deadline_move_request(struct deadline_data *, struct request *);

static inline struct rb_root *
deadline_rb_root(struct deadline_data *dd, struct request *rq)
{
	return &dd->sort_list[rq_data_dir(rq)];
}

/*
 * get the request after `rq' in sector-sorted order
 */
static inline struct request *
deadline_latter_request(struct request *rq)
{
	struct rb_node *node = rb_next(&rq->rb_node);

	if (node)
		return rb_entry_rq(node);

	return NULL;
}

/* ��rq����sort_list����� */
static void
deadline_add_rq_rb(struct deadline_data *dd, struct request *rq)
{
	struct rb_root *root = deadline_rb_root(dd, rq);

	elv_rb_add(root, rq);
}

static inline void
deadline_del_rq_rb(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	if (dd->next_rq[data_dir] == rq)
		dd->next_rq[data_dir] = deadline_latter_request(rq);

	elv_rb_del(deadline_rb_root(dd, rq), rq);
}

/*
 * add rq to rbtree and fifo
 */
/* ��һ������������������� */
static void
deadline_add_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);

	deadline_add_rq_rb(dd, rq); /* ��rq����sort_list����� */

	/*
	 * set expire time and add to fifo list
	 */
	rq_set_fifo_time(rq, jiffies + dd->fifo_expire[data_dir]); /* ��������ʱ�� */
	list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]); /* ��rq����fifo_list */
}

/*
 * remove rq from rbtree and fifo.
 */
/* ��rq������ͺ������ɾ��   */
static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	rq_fifo_clear(rq);
	deadline_del_rq_rb(dd, rq);
}

/* ���bio�ܷ�ϲ������е�ĳ��request��ǰ�� 
 * ����ֻ��ǰ����ļ������������ļ��, ����Ϊ�����Ŀ����Դ�����ǰ���룬
 * �����ͨ�ò㣬�ں˾����˺����ļ���ˣ�������Ǹ��ݵ�������ɢ�б������в�ѯ��
 */
static int
deadline_merge(struct request_queue *q, struct request **req, struct bio *bio)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	struct request *__rq;
	int ret;

	/*
	 * check for front merge
	 */
	/* ��deadline schedulerʹ����front_merges������²Ż����front merge�ļ�� */
	if (dd->front_merges) {
		sector_t sector = bio->bi_sector + bio_sectors(bio); /* ȡbio�����һ������ */

		/* �Ӻ�����в�����ʼ��������sector��ͬ��request */
		__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
		if (__rq) { /* ���ҳɹ� */
			BUG_ON(sector != blk_rq_pos(__rq));

			if (elv_rq_merge_ok(__rq, bio)) { /* �������Եļ�飬ȷ��bio���Բ��� */
				ret = ELEVATOR_FRONT_MERGE;
				goto out;
			}
		}
	}

	return ELEVATOR_NO_MERGE;
out:
	*req = __rq;
	return ret;
}

/* ����bio������ƺ��� */
static void deadline_merged_request(struct request_queue *q,
				    struct request *req, int type)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	/* ������ǽ�bio����request��bio�����ǰ����Ҫ����request���ض�λ */
	if (type == ELEVATOR_FRONT_MERGE) {
		elv_rb_del(deadline_rb_root(dd, req), req); /*��request�Ӻ������ɾ�� */
		deadline_add_rq_rb(dd, req); /* �������������� */
	}
}

/* ��ͨ�ò����request�ĺϲ���deadline_merged_requests()���������ƺ� */
static void
deadline_merged_requests(struct request_queue *q, struct request *req,
			 struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	/* ����Ҫ��֤��������������Ķ��в�Ϊ�գ�Ȼ�����req��next����Ӧ����ʱ�䳤�̣���ѡ�����ĸ���
	 * ������߱�ǰ�ߵ�����ʱ��̣�Ҳ��������Ӧ���Ǿ�Ҫ��next������ʱ�丳��req,
	 * ���ҽ�req���õ�next��fifo_list�е�λ�ã���Ϊnext��Ҫ��ɾ��
	 */
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		/* ���next������ʱ��С��req */
		if (time_before(rq_fifo_time(next), rq_fifo_time(req))) {
			list_move(&req->queuelist, &next->queuelist); /* ����req��fifo��λ�� */
			rq_set_fifo_time(req, rq_fifo_time(next)); /* ����req������ʱ�� */
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	deadline_remove_request(q, next); /* ��next������ͺ������ɾ�� */
}

/*
 * move request from sort list to dispatch queue.
 */
static inline void
deadline_move_to_dispatch(struct deadline_data *dd, struct request *rq)
{
	struct request_queue *q = rq->q;

	deadline_remove_request(q, rq); /* ��rq��fifo_list��sort_list��ɾ�� */
	elv_dispatch_add_tail(q, rq); /* �����������request_queue */
}

/*
 * move an entry to dispatch queue
 */
/* ����Ҫ���ɵ�rq������һ�������ɵ�rq�����ҵ���deadline_move_to_dispatch()���з��ɹ��� */
static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	/* �Ƚ�next_rq���ÿ� */
	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;
	/* ������Ӧ���䷽�����һ��rq��deadline_latter_request()ȡ������д���rq����һ���ڵ� */
	dd->next_rq[data_dir] = deadline_latter_request(rq);

	/* ���õ�ǰ�����rq��ĩβ������ */
	dd->last_sector = rq_end_sector(rq);

	/*
	 * take it off the sort and fifo list, move
	 * to dispatch queue
	 */
	deadline_move_to_dispatch(dd, rq);
}

/*
 * deadline_check_fifo returns 0 if there are no expired requests on the fifo,
 * 1 otherwise. Requires !list_empty(&dd->fifo_list[data_dir])
 */
/* ���jiffies�Ƿ񳬹������������ֵ, ����1Ϊ���޳�ʱ */
static inline int deadline_check_fifo(struct deadline_data *dd, int ddir)
{
	struct request *rq = rq_entry_fifo(dd->fifo_list[ddir].next);

	/*
	 * rq is expired!
	 */
	if (time_after(jiffies, rq_fifo_time(rq)))
		return 1;

	return 0;
}

/*
 * deadline_dispatch_requests selects the best request according to
 * read/write expire, fifo_batch, etc
 */
/* ���������ѡ��request�����ɸ�request_queue */
static int deadline_dispatch_requests(struct request_queue *q, int force)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	/* ȷ����дfifo��״̬ */
	const int reads = !list_empty(&dd->fifo_list[READ]);
	const int writes = !list_empty(&dd->fifo_list[WRITE]);
	struct request *rq;
	int data_dir;

	/*
	 * batches are currently reads XOR writes
	 */
	/* ���next_rq��ָ����rq����ݴ�ȷ����һ�����ɵ�rq���� */
	if (dd->next_rq[WRITE])
		rq = dd->next_rq[WRITE];
	else
		rq = dd->next_rq[READ];

	/* ָ����rq���ҵ�ǰ��batching��С��Ԥ����batch��ֵ������з��ɲ��� */
	if (rq && dd->batching < dd->fifo_batch)
		/* we have a next request are still entitled to batch */
		goto dispatch_request;

	/*
	 * at this point we are not running a batch. select the appropriate
	 * data direction (read / write)
	 */

	/* �������˵��û��ָ��rq,Ҳ����˵Ҫ����Ȩ����ѡ�������һ��rq 
	 * ����Ҫѡ���򣬼�ѡ����������д����
	 */
	if (reads) { /* ������fifo��Ϊ�� */
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ]));
 
 		/* ���д����fifoҲ��Ϊ�գ����ҵ�ǰ��starved��ֵ�Ѿ�������writes_starved����ֵ��  
		 * Ҳ����˵֮ǰ�Ѿ�����������starved���������ˣ�������д����Ķ����ߣ�
		 * ��ѡ�����һ��д����
		 */
		if (writes && (dd->starved++ >= dd->writes_starved))
			goto dispatch_writes;

		data_dir = READ; /* ȷ����һ������Ķ�д����Ϊ�� */

		goto dispatch_find_request;
	}

	/*
	 * there are either no reads or writes have been starved
	 */

	if (writes) {
dispatch_writes:
		/* �ߵ����˵��û�ж����󣬻���д�����ڶ���״̬�����뱻���� */
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[WRITE]));

		dd->starved = 0; /* starved����Ϊ0 */

		data_dir = WRITE; /* ȷ����һ������Ķ�д����Ϊд */

		goto dispatch_find_request;
	}

	return 0;

dispatch_find_request:
	/* ���￪ʼ����ȷ����һ���������ɵ�rq�ĵ�һ��rq */
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	/* ���jiffies�ѳ�����Ӧfifo_list�еĵ�һ��rq������, 
	 * ������һ����������ڵ����������෴�ģ���ȡfifo list�еļ���rq 
	 * һ�ֿ��ܵ�������Ƕ�������࣬����д�������*/
	if (deadline_check_fifo(dd, data_dir) || !dd->next_rq[data_dir]) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		/* ����Ҫ���ɵ�rqΪ�������޵ĵ�һ������ */
		rq = rq_entry_fifo(dd->fifo_list[data_dir].next); 
	} else { /* ���򣬴����������ԵĽǶȿ��ǣ������ϴη��ɵ�rq������һ��rq */
		/*
		 * The last req was the same dir and we have a next request in
		 * sort order. No expired requests so continue on from here.
		 */
		rq = dd->next_rq[data_dir];
	}

	dd->batching = 0;

dispatch_request:
	/*
	 * rq is the selected appropriate request.
	 */
	dd->batching++;
	/* ����Ҫ���ɵ�rq������һ�������ɵ�rq�����ҵ���deadline_move_to_dispatch()���з��ɹ��� */
	deadline_move_request(dd, rq);

	return 1;
}

static int deadline_queue_empty(struct request_queue *q)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	return list_empty(&dd->fifo_list[WRITE])
		&& list_empty(&dd->fifo_list[READ]);
}

/* �ͷ�deadline_data�ṹ */
static void deadline_exit_queue(struct elevator_queue *e)
{
	struct deadline_data *dd = e->elevator_data;

	BUG_ON(!list_empty(&dd->fifo_list[READ]));
	BUG_ON(!list_empty(&dd->fifo_list[WRITE]));

	kfree(dd);
}

/*
 * initialize elevator private data (deadline_data).
 */
/* ���䲢��ʼ��dealline_data�ṹ */
static void *deadline_init_queue(struct request_queue *q)
{
	struct deadline_data *dd;

	dd = kmalloc_node(sizeof(*dd), GFP_KERNEL | __GFP_ZERO, q->node);
	if (!dd)
		return NULL;

	INIT_LIST_HEAD(&dd->fifo_list[READ]);
	INIT_LIST_HEAD(&dd->fifo_list[WRITE]);
	dd->sort_list[READ] = RB_ROOT;
	dd->sort_list[WRITE] = RB_ROOT;
	dd->fifo_expire[READ] = read_expire;
	dd->fifo_expire[WRITE] = write_expire;
	dd->writes_starved = writes_starved;
	dd->front_merges = 1;
	dd->fifo_batch = fifo_batch;
	return dd;
}

/*
 * sysfs parts below
 */

static ssize_t
deadline_var_show(int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
deadline_var_store(int *var, const char *page, size_t count)
{
	char *p = (char *) page;

	*var = simple_strtol(p, &p, 10);
	return count;
}

#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	struct deadline_data *dd = e->elevator_data;			\
	int __data = __VAR;						\
	if (__CONV)							\
		__data = jiffies_to_msecs(__data);			\
	return deadline_var_show(__data, (page));			\
}
SHOW_FUNCTION(deadline_read_expire_show, dd->fifo_expire[READ], 1);
SHOW_FUNCTION(deadline_write_expire_show, dd->fifo_expire[WRITE], 1);
SHOW_FUNCTION(deadline_writes_starved_show, dd->writes_starved, 0);
SHOW_FUNCTION(deadline_front_merges_show, dd->front_merges, 0);
SHOW_FUNCTION(deadline_fifo_batch_show, dd->fifo_batch, 0);
#undef SHOW_FUNCTION

#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct deadline_data *dd = e->elevator_data;			\
	int __data;							\
	int ret = deadline_var_store(&__data, (page), count);		\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	if (__CONV)							\
		*(__PTR) = msecs_to_jiffies(__data);			\
	else								\
		*(__PTR) = __data;					\
	return ret;							\
}
STORE_FUNCTION(deadline_read_expire_store, &dd->fifo_expire[READ], 0, INT_MAX, 1);
STORE_FUNCTION(deadline_write_expire_store, &dd->fifo_expire[WRITE], 0, INT_MAX, 1);
STORE_FUNCTION(deadline_writes_starved_store, &dd->writes_starved, INT_MIN, INT_MAX, 0);
STORE_FUNCTION(deadline_front_merges_store, &dd->front_merges, 0, 1, 0);
STORE_FUNCTION(deadline_fifo_batch_store, &dd->fifo_batch, 0, INT_MAX, 0);
#undef STORE_FUNCTION

#define DD_ATTR(name) \
	__ATTR(name, S_IRUGO|S_IWUSR, deadline_##name##_show, \
				      deadline_##name##_store)

static struct elv_fs_entry deadline_attrs[] = {
	DD_ATTR(read_expire),
	DD_ATTR(write_expire),
	DD_ATTR(writes_starved),
	DD_ATTR(front_merges),
	DD_ATTR(fifo_batch),
	__ATTR_NULL
};

static struct elevator_type iosched_deadline = {
	.ops = {
		.elevator_merge_fn = 		deadline_merge,
		.elevator_merged_fn =		deadline_merged_request,
		.elevator_merge_req_fn =	deadline_merged_requests,
		.elevator_dispatch_fn =		deadline_dispatch_requests,
		.elevator_add_req_fn =		deadline_add_request,
		.elevator_queue_empty_fn =	deadline_queue_empty,
		.elevator_former_req_fn =	elv_rb_former_request,
		.elevator_latter_req_fn =	elv_rb_latter_request,
		.elevator_init_fn =		deadline_init_queue,
		.elevator_exit_fn =		deadline_exit_queue,
	},

	.elevator_attrs = deadline_attrs,
	.elevator_name = "deadline",
	.elevator_owner = THIS_MODULE,
};

static int __init deadline_init(void)
{
	elv_register(&iosched_deadline);

	return 0;
}

static void __exit deadline_exit(void)
{
	elv_unregister(&iosched_deadline);
}

module_init(deadline_init);
module_exit(deadline_exit);

MODULE_AUTHOR("Jens Axboe");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("deadline IO scheduler");
