/*
 * IPVS:        Weighted Round-Robin Scheduling module
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Changes:
 *     Wensong Zhang            :     changed the ip_vs_wrr_schedule to return dest
 *     Wensong Zhang            :     changed some comestics things for debugging
 *     Wensong Zhang            :     changed for the d-linked destination list
 *     Wensong Zhang            :     added the ip_vs_wrr_update_svc
 *     Julian Anastasov         :     fixed the bug of returning destination
 *                                    with weight 0 when all weights are zero
 *
 */

#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>

#include <net/ip_vs.h>

/*
 * current destination pointer for weighted round-robin scheduling
 */
struct ip_vs_wrr_mark {
	struct list_head *cl;	/* current list head *//* 当前dest节点 */
	int cw;			/* current weight */ /* 当前权重 */
	int mw;			/* maximum weight *//* 最大权重 */
	int di;			/* decreasing interval *//* 所有权重值的最大公约数 */
};


/*
 *    Get the gcd of server weights
 */
static int gcd(int a, int b)
{
	int c;

	while ((c = a % b)) {
		a = b;
		b = c;
	}
	return b;
}

/* 求所有权重的最大公约数 */
static int ip_vs_wrr_gcd_weight(struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest;
	int weight;
	int g = 0;

	list_for_each_entry(dest, &svc->destinations, n_list) {
		weight = atomic_read(&dest->weight);
		if (weight > 0) {
			if (g > 0)
				g = gcd(weight, g);
			else
				g = weight;
		}
	}
	return g ? g : 1;
}


/*
 *    Get the maximum weight of the service destinations.
 */
/* 遍历ip_vs_dest节点查找其中最大的weight权重 */
static int ip_vs_wrr_max_weight(struct ip_vs_service *svc)
{
	struct ip_vs_dest *dest;
	int new_weight, weight = 0;

	list_for_each_entry(dest, &svc->destinations, n_list) {
		new_weight = atomic_read(&dest->weight);
		if (new_weight > weight)
			weight = new_weight;
	}

	return weight;
}


static int ip_vs_wrr_init_svc(struct ip_vs_service *svc)
{
	struct ip_vs_wrr_mark *mark;

	/*
	 *    Allocate the mark variable for WRR scheduling
	 */
	mark = kmalloc(sizeof(struct ip_vs_wrr_mark), GFP_ATOMIC);
	if (mark == NULL) {
		pr_err("%s(): no memory\n", __func__);
		return -ENOMEM;
	}
	mark->cl = &svc->destinations;
	mark->cw = 0;
	mark->mw = ip_vs_wrr_max_weight(svc); /* 查找最大的weight */
	mark->di = ip_vs_wrr_gcd_weight(svc); /* 求所有权重的最大公约数 */
	svc->sched_data = mark;

	return 0;
}


static int ip_vs_wrr_done_svc(struct ip_vs_service *svc)
{
	/*
	 *    Release the mark variable
	 */
	kfree(svc->sched_data);

	return 0;
}


static int ip_vs_wrr_update_svc(struct ip_vs_service *svc)
{
	struct ip_vs_wrr_mark *mark = svc->sched_data;

	mark->cl = &svc->destinations;
	mark->mw = ip_vs_wrr_max_weight(svc);
	mark->di = ip_vs_wrr_gcd_weight(svc);
	if (mark->cw > mark->mw)
		mark->cw = 0;
	return 0;
}


/*
 *    Weighted Round-Robin Scheduling
 */
/* wrr调度算法 
 *
 * init: 
 * 	mx = MAX(weight)
 * 	di = gcd(weight)
 * 	cw = 0
 * 
 * loop_2: 	cw = mx
 * loop_1	find (all) dest if (dest.weight >= cw)
 * 		cw -= di
 * 		if (cw > 0) goto loop_1
 * 		else goto loop_2
 *
 */
static struct ip_vs_dest *
ip_vs_wrr_schedule(struct ip_vs_service *svc, const struct sk_buff *skb)
{
	struct ip_vs_dest *dest;
	struct ip_vs_wrr_mark *mark = svc->sched_data;
	struct list_head *p;

	IP_VS_DBG(6, "%s(): Scheduling...\n", __func__);

	/*
	 * This loop will always terminate, because mark->cw in (0, max_weight]
	 * and at least one server has its weight equal to max_weight.
	 */
	write_lock(&svc->sched_lock);
	p = mark->cl;
	while (1) {
		if (mark->cl == &svc->destinations) { /* 轮询到节点链表的开头 */
			/* it is at the head of the destination list */

			if (mark->cl == mark->cl->next) { /* 没有节点,结束 */
				/* no dest entry */
				IP_VS_ERR_RL("WRR: no destination available: "
					     "no destinations present\n");
				dest = NULL;
				goto out;
			}

			mark->cl = svc->destinations.next; /* cl指向第一个节点 */
			mark->cw -= mark->di; /* 轮询一圈后cw每次减小最大公约数 */
			if (mark->cw <= 0) { /* cw减到0后，重置为最大weight */
				mark->cw = mark->mw; /* cw置为最大weight */
				/*
				 * Still zero, which means no available servers.
				 */
				if (mark->cw == 0) { /* 没有节点，结束 */
					mark->cl = &svc->destinations;
					IP_VS_ERR_RL("WRR: no destination "
						     "available\n");
					dest = NULL;
					goto out;
				}
			}
		} else
			mark->cl = mark->cl->next; /* 下一个结点 */

		if (mark->cl != &svc->destinations) { /* 如果不是链表头 */
			/* not at the head of the list */
			dest = list_entry(mark->cl, struct ip_vs_dest, n_list); /* 获取cl对应的节点 */
			if (!(dest->flags & IP_VS_DEST_F_OVERLOAD) &&
			    atomic_read(&dest->weight) >= mark->cw) {
				/* 当节点的weight值大于cw值，即找到 */
				/* got it */
				break;
			}
		}

		if (mark->cl == p && mark->cw == mark->di) {
			/* back to the start, and no dest is found.
			   It is only possible when all dests are OVERLOADED */
			dest = NULL;
			IP_VS_ERR_RL("WRR: no destination available: "
				     "all destinations are overloaded\n");
			goto out;
		}
	}

	IP_VS_DBG_BUF(6, "WRR: server %s:%u "
		      "activeconns %d refcnt %d weight %d\n",
		      IP_VS_DBG_ADDR(svc->af, &dest->addr), ntohs(dest->port),
		      atomic_read(&dest->activeconns),
		      atomic_read(&dest->refcnt),
		      atomic_read(&dest->weight));

  out:
	write_unlock(&svc->sched_lock);
	return dest;
}


static struct ip_vs_scheduler ip_vs_wrr_scheduler = {
	.name =			"wrr",
	.refcnt =		ATOMIC_INIT(0),
	.module =		THIS_MODULE,
	.n_list =		LIST_HEAD_INIT(ip_vs_wrr_scheduler.n_list),
	.init_service =		ip_vs_wrr_init_svc,
	.done_service =		ip_vs_wrr_done_svc,
	.update_service =	ip_vs_wrr_update_svc,
	.schedule =		ip_vs_wrr_schedule,
};

static int __init ip_vs_wrr_init(void)
{
	return register_ip_vs_scheduler(&ip_vs_wrr_scheduler) ;
}

static void __exit ip_vs_wrr_cleanup(void)
{
	unregister_ip_vs_scheduler(&ip_vs_wrr_scheduler);
}

module_init(ip_vs_wrr_init);
module_exit(ip_vs_wrr_cleanup);
MODULE_LICENSE("GPL");
