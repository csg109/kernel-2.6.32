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
static const int read_expire = HZ / 2;  /* max time before a read is submitted. *//* 读超时时间0.5S */
static const int write_expire = 5 * HZ; /* ditto for writes, these limits are SOFT! *//* 写超时时间5S */

/* writes_starved默认为2，可以理解为写请求的饥饿线，
 * 内核总是优先处理读请求，starved表明当前处理的读请求批数，
 * 只有starved超过了writes_starved后，才会去考虑写请求。
 * 因此，假如一个写请求的期限已经超过，该请求也不一定会被立刻响应，
 * 因为读请求的batch还没处理完，即使处理完，
 * 也必须等到starved超过writes_starved才有机会被响应  
 */
static const int writes_starved = 2;    /* max times reads can starve a write */
					/* 写请求的饥饿数，当连续writes_starved次批处理了读请求后，
					 * 必须处理写请求，防止写请求饿死 */
static const int fifo_batch = 16;       /* # of sequential requests treated as one
				     by the above parameters. For throughput. */
				     	/* 一次批处理连续的请求数 */

struct deadline_data {
	/*
	 * run time data
	 */

	/*
	 * requests (deadline_rq s) are present on both sort_list and fifo_list
	 */
	struct rb_root sort_list[2];	/* 读写请求的红黑树，以请求的起始扇区来排序 */
	struct list_head fifo_list[2]; 	/* 读写请求的链表，以请求的响应期限来排序 */

	/*
	 * next in sort order. read, write or both are NULL
	 */
	struct request *next_rq[2]; 	/* 下一个读(写)请求，当确定一个批量传输时，
					 * 通过该指针直接获取下一个请求 */
	unsigned int batching;		/* number of sequential requests made */
					/* 批量传输的当前值 */
					/* 用于记录当前连续提交的request数目。当batching < fifo_batch，
					 * 都可以继续进行连续提交  */
	sector_t last_sector;		/* head position */
					/* 处理的rq的末尾扇区号 */
	unsigned int starved;		/* times reads have starved writes */
					/* 标识着当前是第starved批读请求传输 */
					/* 如果starved超过writes_starved，则需要提交写request，从而避免写饥饿 */

	/*
	 * settings that change how the i/o scheduler behaves
	 */
	int fifo_expire[2]; 		/* 读写请求的期限值 */
	int fifo_batch; 		/* 批量传输的请求数 */
	int writes_starved; 		/* 写请求的饿死线，
					 * 传输了writes_starved批读请求后，必须传输写请求 */
	int front_merges; 		/* 是否使能front merge的检查 
					 * 置1为启用向前合并, 即允许在request的前面插入bio */
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

/* 将rq插入sort_list红黑树 */
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
/* 将一个新请求添加至调度器 */
static void
deadline_add_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	const int data_dir = rq_data_dir(rq);

	deadline_add_rq_rb(dd, rq); /* 将rq插入sort_list红黑树 */

	/*
	 * set expire time and add to fifo list
	 */
	rq_set_fifo_time(rq, jiffies + dd->fifo_expire[data_dir]); /* 设置期限时间 */
	list_add_tail(&rq->queuelist, &dd->fifo_list[data_dir]); /* 将rq插入fifo_list */
}

/*
 * remove rq from rbtree and fifo.
 */
/* 将rq从链表和红黑树中删除   */
static void deadline_remove_request(struct request_queue *q, struct request *rq)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	rq_fifo_clear(rq);
	deadline_del_rq_rb(dd, rq);
}

/* 检查bio能否合并入现有的某个request的前面 
 * 这里只做前插入的检查而不做后插入的检查, 是因为后插入的可能性大大高于前插入，
 * 因此在通用层，内核就做了后插入的检查了，后插入是根据调度器的散列表来进行查询的
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
	/* 在deadline scheduler使能了front_merges的情况下才会进行front merge的检查 */
	if (dd->front_merges) {
		sector_t sector = bio->bi_sector + bio_sectors(bio); /* 取bio的最后一个扇区 */

		/* 从红黑树中查找起始扇区号与sector相同的request */
		__rq = elv_rb_find(&dd->sort_list[bio_data_dir(bio)], sector);
		if (__rq) { /* 查找成功 */
			BUG_ON(sector != blk_rq_pos(__rq));

			if (elv_rq_merge_ok(__rq, bio)) { /* 各项属性的检查，确定bio可以插入 */
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

/* 进行bio插入的善后工作 */
static void deadline_merged_request(struct request_queue *q,
				    struct request *req, int type)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	/*
	 * if the merge was a front merge, we need to reposition request
	 */
	/* 如果是是将bio插入request的bio链表的前面则要进行request的重定位 */
	if (type == ELEVATOR_FRONT_MERGE) {
		elv_rb_del(deadline_rb_root(dd, req), req); /*将request从红黑树中删除 */
		deadline_add_rq_rb(dd, req); /* 重新添加至红黑树 */
	}
}

/* 在通用层进行request的合并后，deadline_merged_requests()函数负责善后 */
static void
deadline_merged_requests(struct request_queue *q, struct request *req,
			 struct request *next)
{
	/*
	 * if next expires before rq, assign its expire time to rq
	 * and move into next position (next will be deleted) in fifo
	 */
	/* 首先要保证两个请求的所属的队列不为空，然后根据req和next的响应期限时间长短，来选择保留哪个，
	 * 如果后者比前者的期限时间短，也就是先响应，那就要将next的期限时间赋给req,
	 * 并且将req放置到next在fifo_list中的位置，因为next将要被删除
	 */
	if (!list_empty(&req->queuelist) && !list_empty(&next->queuelist)) {
		/* 如果next的期限时间小于req */
		if (time_before(rq_fifo_time(next), rq_fifo_time(req))) {
			list_move(&req->queuelist, &next->queuelist); /* 调整req在fifo的位置 */
			rq_set_fifo_time(req, rq_fifo_time(next)); /* 重置req的期限时间 */
		}
	}

	/*
	 * kill knowledge of next, this one is a goner
	 */
	deadline_remove_request(q, next); /* 将next从链表和红黑树中删除 */
}

/*
 * move request from sort list to dispatch queue.
 */
static inline void
deadline_move_to_dispatch(struct deadline_data *dd, struct request *rq)
{
	struct request_queue *q = rq->q;

	deadline_remove_request(q, rq); /* 将rq从fifo_list和sort_list中删除 */
	elv_dispatch_add_tail(q, rq); /* 添加至所属的request_queue */
}

/*
 * move an entry to dispatch queue
 */
/* 根据要分派的rq设置下一个待分派的rq，并且调用deadline_move_to_dispatch()进行分派工作 */
static void
deadline_move_request(struct deadline_data *dd, struct request *rq)
{
	const int data_dir = rq_data_dir(rq);

	/* 先将next_rq都置空 */
	dd->next_rq[READ] = NULL;
	dd->next_rq[WRITE] = NULL;
	/* 设置相应传输方向的下一个rq，deadline_latter_request()取红黑树中大于rq的下一个节点 */
	dd->next_rq[data_dir] = deadline_latter_request(rq);

	/* 设置当前处理的rq的末尾扇区号 */
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
/* 检查jiffies是否超过了请求的期限值, 返回1为期限超时 */
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
/* 调度器如何选择request，分派给request_queue */
static int deadline_dispatch_requests(struct request_queue *q, int force)
{
	struct deadline_data *dd = q->elevator->elevator_data;
	/* 确定读写fifo的状态 */
	const int reads = !list_empty(&dd->fifo_list[READ]);
	const int writes = !list_empty(&dd->fifo_list[WRITE]);
	struct request *rq;
	int data_dir;

	/*
	 * batches are currently reads XOR writes
	 */
	/* 如果next_rq中指定了rq，则据此确定下一个分派的rq对象 */
	if (dd->next_rq[WRITE])
		rq = dd->next_rq[WRITE];
	else
		rq = dd->next_rq[READ];

	/* 指定了rq并且当前的batching数小于预定的batch数值，则进行分派操作 */
	if (rq && dd->batching < dd->fifo_batch)
		/* we have a next request are still entitled to batch */
		goto dispatch_request;

	/*
	 * at this point we are not running a batch. select the appropriate
	 * data direction (read / write)
	 */

	/* 到了这里，说明没有指定rq,也就是说要进行权衡来选择分派哪一个rq 
	 * 首先要选择方向，即选定读请求还是写请求
	 */
	if (reads) { /* 读请求fifo不为空 */
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[READ]));
 
 		/* 如果写请求fifo也不为空，并且当前的starved数值已经超过了writes_starved的数值，  
		 * 也就是说之前已经连续处理了starved个读请求了，超过了写请求的饿死线，
		 * 则选择分派一个写请求
		 */
		if (writes && (dd->starved++ >= dd->writes_starved))
			goto dispatch_writes;

		data_dir = READ; /* 确定下一个请求的读写方向为读 */

		goto dispatch_find_request;
	}

	/*
	 * there are either no reads or writes have been starved
	 */

	if (writes) {
dispatch_writes:
		/* 走到这里，说明没有读请求，或者写请求处于饿死状态，必须被处理 */
		BUG_ON(RB_EMPTY_ROOT(&dd->sort_list[WRITE]));

		dd->starved = 0; /* starved重置为0 */

		data_dir = WRITE; /* 确定下一个请求的读写方向为写 */

		goto dispatch_find_request;
	}

	return 0;

dispatch_find_request:
	/* 这里开始重新确定下一批连续分派的rq的第一个rq */
	/*
	 * we are not running a batch, find best request for selected data_dir
	 */
	/* 如果jiffies已超过相应fifo_list中的第一个rq的期限, 
	 * 或者上一个请求和现在的请求方向是相反的，则取fifo list中的饥饿rq 
	 * 一种可能的情况就是读请求过多，导致写请求饿死*/
	if (deadline_check_fifo(dd, data_dir) || !dd->next_rq[data_dir]) {
		/*
		 * A deadline has expired, the last request was in the other
		 * direction, or we have run out of higher-sectored requests.
		 * Start again from the request with the earliest expiry time.
		 */
		/* 设置要分派的rq为超过期限的第一个请求 */
		rq = rq_entry_fifo(dd->fifo_list[data_dir].next); 
	} else { /* 否则，从扇区连续性的角度考虑，接着上次分派的rq继续下一个rq */
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
	/* 根据要分派的rq设置下一个待分派的rq，并且调用deadline_move_to_dispatch()进行分派工作 */
	deadline_move_request(dd, rq);

	return 1;
}

static int deadline_queue_empty(struct request_queue *q)
{
	struct deadline_data *dd = q->elevator->elevator_data;

	return list_empty(&dd->fifo_list[WRITE])
		&& list_empty(&dd->fifo_list[READ]);
}

/* 释放deadline_data结构 */
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
/* 分配并初始化dealline_data结构 */
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
