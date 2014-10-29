#ifndef _LINUX_ELEVATOR_H
#define _LINUX_ELEVATOR_H

#include <linux/percpu.h>

#ifdef CONFIG_BLOCK

typedef int (elevator_merge_fn) (struct request_queue *, struct request **,
				 struct bio *);

typedef void (elevator_merge_req_fn) (struct request_queue *, struct request *, struct request *);

typedef void (elevator_merged_fn) (struct request_queue *, struct request *, int);

typedef int (elevator_allow_merge_fn) (struct request_queue *, struct request *, struct bio *);

typedef void (elevator_bio_merged_fn) (struct request_queue *,
						struct request *, struct bio *);

typedef int (elevator_dispatch_fn) (struct request_queue *, int);

typedef void (elevator_add_req_fn) (struct request_queue *, struct request *);
typedef int (elevator_queue_empty_fn) (struct request_queue *);
typedef struct request *(elevator_request_list_fn) (struct request_queue *, struct request *);
typedef void (elevator_completed_req_fn) (struct request_queue *, struct request *);
typedef int (elevator_may_queue_fn) (struct request_queue *, int);

typedef int (elevator_set_req_fn) (struct request_queue *, struct request *, gfp_t);
typedef void (elevator_put_req_fn) (struct request *);
typedef void (elevator_activate_req_fn) (struct request_queue *, struct request *);
typedef void (elevator_deactivate_req_fn) (struct request_queue *, struct request *);

typedef void *(elevator_init_fn) (struct request_queue *);
typedef void (elevator_exit_fn) (struct elevator_queue *);

struct elevator_ops
{
	/* 检查一个新的请求是否可以与请求队列中某个现存请求合并 */
	elevator_merge_fn *elevator_merge_fn;
	/* 在两个请求尝试合并但不能合并 之后调用 */
	elevator_merged_fn *elevator_merged_fn;
	/* 将两个请求合并成一个 */
	elevator_merge_req_fn *elevator_merge_req_fn;
	/* 判断bio是否允许合并到request中 */
	elevator_allow_merge_fn *elevator_allow_merge_fn;

	/* 将bio并入request时被调用 */
	elevator_bio_merged_fn *elevator_bio_merged_fn;

	/* 从给定的请求队列中选择下一步应该调度执行的请求 
	 * 即调度器如何选择request，分派给request_queue 
	 */
	elevator_dispatch_fn *elevator_dispatch_fn;

	/* 像调度器添加新的请求  */
	elevator_add_req_fn *elevator_add_req_fn;
	elevator_activate_req_fn *elevator_activate_req_fn;
	elevator_deactivate_req_fn *elevator_deactivate_req_fn;

	/* 检查是否包含可供处理的请求, 在request_queue->queue_head队列为空时被调用 */
	elevator_queue_empty_fn *elevator_queue_empty_fn; 
	/* 请求完成时进行的一些操作 */
	elevator_completed_req_fn *elevator_completed_req_fn;

	/* 查找给定请求的前一个请求,在合并请求时很有用 */
	elevator_request_list_fn *elevator_former_req_fn;
	/* 查找给定请求的后一个请求,在合并请求时很有用 */
	elevator_request_list_fn *elevator_latter_req_fn;

	/* 创建新请求时调用 */
	elevator_set_req_fn *elevator_set_req_fn;
	/* 释放请求回内存管理系统时调用 */
	elevator_put_req_fn *elevator_put_req_fn;

	/* 分配一个新request前调用 */
	elevator_may_queue_fn *elevator_may_queue_fn;

	/* 在队列初始化时调用，等同于构造函数 */
	elevator_init_fn *elevator_init_fn;
	/* 在队列释放时调用， 等同于析构函数 */
	elevator_exit_fn *elevator_exit_fn;
	void (*trim)(struct io_context *);
};

#define ELV_NAME_MAX	(16)

struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};

/*
 * identifies an elevator type, such as AS or deadline
 */
struct elevator_type
{
	struct list_head list; 		/* 内核中所有调度器链表，表头为elv_list */
	struct elevator_ops ops; 	/* IO调度器操作 */
	struct elv_fs_entry *elevator_attrs; 	/* sysfs中的属性，用于微调调度器 */
	char elevator_name[ELV_NAME_MAX]; 	/* 调度器名称 */
	struct module *elevator_owner;
};

/*
 * each queue has an elevator_queue associated with it
 */
struct elevator_queue
{
	struct elevator_ops *ops;
	void *elevator_data; 			/* 调度器私有数据 */
	struct kobject kobj;
	struct elevator_type *elevator_type; 	/* 调度器类型 */
	struct mutex sysfs_lock;
	struct hlist_head *hash; 		/* 哈希表，用来快速找到可以被bio并入的request */
	/*
	 * struct elevator_queue:s are always allocated using
	 * elevator_alloc, so it's safe to hang this bitfield off of
	 * the end.
	 */
#ifndef __GENKSYMS__
	unsigned int registered:1;
#endif
};

/*
 * block elevator interface
 */
extern void elv_dispatch_sort(struct request_queue *, struct request *);
extern void elv_dispatch_add_tail(struct request_queue *, struct request *);
extern void elv_add_request(struct request_queue *, struct request *, int, int);
extern void __elv_add_request(struct request_queue *, struct request *, int, int);
extern void elv_insert(struct request_queue *, struct request *, int);
extern int elv_merge(struct request_queue *, struct request **, struct bio *);
extern void elv_merge_requests(struct request_queue *, struct request *,
			       struct request *);
extern void elv_merged_request(struct request_queue *, struct request *, int);
extern void elv_bio_merged(struct request_queue *q, struct request *,
				struct bio *);
extern void elv_requeue_request(struct request_queue *, struct request *);
extern int elv_queue_empty(struct request_queue *);
extern struct request *elv_former_request(struct request_queue *, struct request *);
extern struct request *elv_latter_request(struct request_queue *, struct request *);
extern int elv_register_queue(struct request_queue *q);
extern void elv_unregister_queue(struct request_queue *q);
extern int elv_may_queue(struct request_queue *, int);
extern void elv_abort_queue(struct request_queue *);
extern void elv_completed_request(struct request_queue *, struct request *);
extern int elv_set_request(struct request_queue *, struct request *, gfp_t);
extern void elv_put_request(struct request_queue *, struct request *);
extern void elv_drain_elevator(struct request_queue *);

/*
 * io scheduler registration
 */
extern void elv_register(struct elevator_type *);
extern void elv_unregister(struct elevator_type *);

/*
 * io scheduler sysfs switching
 */
extern ssize_t elv_iosched_show(struct request_queue *, char *);
extern ssize_t elv_iosched_store(struct request_queue *, const char *, size_t);

extern int elevator_init(struct request_queue *, char *);
extern void elevator_exit(struct elevator_queue *);
extern int elevator_change(struct request_queue *, const char *);
extern int elv_rq_merge_ok(struct request *, struct bio *);

/*
 * Helper functions.
 */
extern struct request *elv_rb_former_request(struct request_queue *, struct request *);
extern struct request *elv_rb_latter_request(struct request_queue *, struct request *);

/*
 * rb support functions.
 */
extern void elv_rb_add(struct rb_root *, struct request *);
extern void elv_rb_del(struct rb_root *, struct request *);
extern struct request *elv_rb_find(struct rb_root *, sector_t);

/*
 * Return values from elevator merger
 */
#define ELEVATOR_NO_MERGE	0 	/* 已经存在的请求中不能包含bio结构 */
#define ELEVATOR_FRONT_MERGE	1 	/* bio结构可作为某个请求req的第一个bio被插入 */
#define ELEVATOR_BACK_MERGE	2 	/* bio结构可作为末尾的bio插入某个请求req中 */

/*
 * Insertion selection
 */
#define ELEVATOR_INSERT_FRONT	1
#define ELEVATOR_INSERT_BACK	2
#define ELEVATOR_INSERT_SORT	3 	/* 按照request所含的数据块的盘块顺序插入 */
#define ELEVATOR_INSERT_REQUEUE	4
#define ELEVATOR_INSERT_FLUSH	5

/*
 * return values from elevator_may_queue_fn
 */
enum {
	ELV_MQUEUE_MAY,
	ELV_MQUEUE_NO,
	ELV_MQUEUE_MUST,
};

#define rq_end_sector(rq)	(blk_rq_pos(rq) + blk_rq_sectors(rq))
#define rb_entry_rq(node)	rb_entry((node), struct request, rb_node)

/*
 * Hack to reuse the csd.list list_head as the fifo time holder while
 * the request is in the io scheduler. Saves an unsigned long in rq.
 */
#define rq_fifo_time(rq)	((unsigned long) (rq)->csd.list.next)
#define rq_set_fifo_time(rq,exp)	((rq)->csd.list.next = (void *) (exp))
#define rq_entry_fifo(ptr)	list_entry((ptr), struct request, queuelist)
#define rq_fifo_clear(rq)	do {		\
	list_del_init(&(rq)->queuelist);	\
	INIT_LIST_HEAD(&(rq)->csd.list);	\
	} while (0)

/*
 * io context count accounting
 */
#define elv_ioc_count_mod(name, __val)				\
	do {							\
		preempt_disable();				\
		__get_cpu_var(name) += (__val);			\
		preempt_enable();				\
	} while (0)

#define elv_ioc_count_inc(name)	elv_ioc_count_mod(name, 1)
#define elv_ioc_count_dec(name)	elv_ioc_count_mod(name, -1)

#define elv_ioc_count_read(name)				\
({								\
	unsigned long __val = 0;				\
	int __cpu;						\
	smp_wmb();						\
	for_each_possible_cpu(__cpu)				\
		__val += per_cpu(name, __cpu);			\
	__val;							\
})

#endif /* CONFIG_BLOCK */
#endif
