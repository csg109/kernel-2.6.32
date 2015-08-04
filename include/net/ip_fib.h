/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET  is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Forwarding Information Base.
 *
 * Authors:	A.N.Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IP_FIB_H
#define _NET_IP_FIB_H

#include <net/flow.h>
#include <linux/seq_file.h>
#include <net/fib_rules.h>

struct fib_config {
	u8			fc_dst_len;
	u8			fc_tos;
	u8			fc_protocol;
	u8			fc_scope;
	u8			fc_type;
	/* 3 bytes unused */
	u32			fc_table;
	__be32			fc_dst;
	__be32			fc_gw;
	int			fc_oif;
	u32			fc_flags;
	u32			fc_priority;
	__be32			fc_prefsrc;
	struct nlattr		*fc_mx;
	struct rtnexthop	*fc_mp;
	int			fc_mx_len;
	int			fc_mp_len;
	u32			fc_flow;
	u32			fc_nlflags;
	struct nl_info		fc_nlinfo;
 };

struct fib_info;

struct fib_nh { /* 存放着下一跳路由的地址(nh_gw) */
	struct net_device	*nh_dev;	/* 该路由表项输出网络设备 */
	struct hlist_node	nh_hash;	/* 用于将nh_hash链入散列表 */
	struct fib_info		*nh_parent;	/* 指向所属的路由表项fib_info */
	unsigned		nh_flags;	/* 一些标志，如RTM_F_NOTIFY等值 */
	unsigned char		nh_scope;	/* 路由范围 */
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	/* 当支持多路径路由时，用来实现加权随机轮转算法 */
	int			nh_weight; 	
	int			nh_power;
#endif
#ifdef CONFIG_NET_CLS_ROUTE
	__u32			nh_tclassid;	/* 基于策略路由的分配标签 */
#endif
	int			nh_oif;		/* 该路由表项的输出网络设备索引 */
	__be32			nh_gw;		/* 路由项的网关地址 */
};

/*
 * This structure contains data shared by many of routes.
 */

struct fib_info { /* 存储下一跳网关等, 多个fib_alias可能共享一个fib_info */
	struct hlist_node	fib_hash; 	/* 将所有的fib_info都链入fib_info_hash中 */
	struct hlist_node	fib_lhash;	/* 将fib_info插入fib_info_laddrhash中，
						 *在路由表项中有一个首选源地址时，才插入到fib_info_laddrhash 
						 */
	struct net		*fib_net;
	int			fib_treeref; 	/* 持有该fib_info的fib_node数目 */
	atomic_t		fib_clntref;	/* 由于路由查找成功而被持有的引用计数 */
	int			fib_dead;	/* 路由表项正在被删除的标志，当为1时警告将被删除而不能再使用 */
	unsigned		fib_flags;	/* 现在只有一个标志RTNH_F_DEAD，表示已无效 */
	int			fib_protocol;	/* 设置路由的协议, 有RTPROT_UNSPEC等值 */
	__be32			fib_prefsrc;	/* 首选源IP地址 */
	u32			fib_priority;	/* 路由优先级，越小优先级越高, 当没有设置时默认为0 */
	u32			fib_metrics[RTAX_MAX]; /* 与路由相关的度量值, 如RTAX_RTT等值 */
#define fib_mtu fib_metrics[RTAX_MTU-1]
#define fib_window fib_metrics[RTAX_WINDOW-1]
#define fib_rtt fib_metrics[RTAX_RTT-1]
#define fib_advmss fib_metrics[RTAX_ADVMSS-1]
	int			fib_nhs;
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	int			fib_power; 	/* 当内核编译支持多路径路由时，用于实现加权随机轮转算法 */
#endif
	struct fib_nh		fib_nh[0]; 	/* 支持多路径路由时的下一跳散列表 */
#define fib_dev		fib_nh[0].nh_dev	
};


#ifdef CONFIG_IP_MULTIPLE_TABLES
struct fib_rule;
#endif

struct fib_result {
	unsigned char	prefixlen; 	/* 返回路由表项的网络掩码长度 */
	unsigned char	nh_sel;		/* 返回选择路径的序号，通常为0，多路径路由才可能大于0 */
	unsigned char	type;		/* 返回路由表项的类型 */
	unsigned char	scope;		/* 返回路由表项的作用范围 */
	struct fib_info *fi;		/* 返回查找到的路由信息 */
#ifdef CONFIG_IP_MULTIPLE_TABLES
	struct fib_rule	*r;		/* 支持策略路由时，查找到的路由策略 */
#endif
};

struct fib_result_nl {
	__be32		fl_addr;   /* To be looked up*/
	u32		fl_mark;
	unsigned char	fl_tos;
	unsigned char   fl_scope;
	unsigned char   tb_id_in;

	unsigned char   tb_id;      /* Results */
	unsigned char	prefixlen;
	unsigned char	nh_sel;
	unsigned char	type;
	unsigned char	scope;
	int             err;      
};

#ifdef CONFIG_IP_ROUTE_MULTIPATH

#define FIB_RES_NH(res)		((res).fi->fib_nh[(res).nh_sel])

#define FIB_TABLE_HASHSZ 2

#else /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_NH(res)		((res).fi->fib_nh[0])

#define FIB_TABLE_HASHSZ 256

#endif /* CONFIG_IP_ROUTE_MULTIPATH */

#define FIB_RES_PREFSRC(res)		((res).fi->fib_prefsrc ? : __fib_res_prefsrc(&res))
#define FIB_RES_GW(res)			(FIB_RES_NH(res).nh_gw)
#define FIB_RES_DEV(res)		(FIB_RES_NH(res).nh_dev)
#define FIB_RES_OIF(res)		(FIB_RES_NH(res).nh_oif)

struct fib_table { /* 路由表结构，链接在全局fib_table_hash中 */
	struct hlist_node tb_hlist;
	u32		tb_id;	/* 路由表ID标识, rt_class_t中定义了保留的路由表 */
	int		tb_default;
	/* 用于在当前路由表搜索符合条件的路由表项，FIB_HASH算法中为fn_hash_lookup() */
	int		(*tb_lookup)(struct fib_table *tb, const struct flowi *flp, struct fib_result *res);
	/* 用于在当前路由表中插入给定的路由表项，FIB_HASH算法中为fn_hash_insert() */
	int		(*tb_insert)(struct fib_table *, struct fib_config *);
	/* 用于在当前路由表中删除符合条件的路由表项，FIB_HASH算法中为fn_hash_delete() */
	int		(*tb_delete)(struct fib_table *, struct fib_config *);
	/* dump出路由表的内容, FIB_HASH算法中为fn_hash_dump() */
	int		(*tb_dump)(struct fib_table *table, struct sk_buff *skb,
				     struct netlink_callback *cb);
	/* 删除设置有RTNH_F_DEAD标志的fib_info结构实例，在FIB_HASH算法中为fn_hash_flush() */
	int		(*tb_flush)(struct fib_table *table);
	/* 选择一条默认路由，FIB_HASH算法中为fn_hash_select_default() */
	void		(*tb_select_default)(struct fib_table *table,
					     const struct flowi *flp, struct fib_result *res);

	unsigned char	tb_data[0]; /* 0长度数组，地址为fib_table后接的的fn_hash结构 */
};

#ifndef CONFIG_IP_MULTIPLE_TABLES

#define TABLE_LOCAL_INDEX	0
#define TABLE_MAIN_INDEX	1

static inline struct fib_table *fib_get_table(struct net *net, u32 id)
{
	struct hlist_head *ptr;

	ptr = id == RT_TABLE_LOCAL ?
		&net->ipv4.fib_table_hash[TABLE_LOCAL_INDEX] :
		&net->ipv4.fib_table_hash[TABLE_MAIN_INDEX];
	return hlist_entry(ptr->first, struct fib_table, tb_hlist);
}

static inline struct fib_table *fib_new_table(struct net *net, u32 id)
{
	return fib_get_table(net, id);
}

/* 搜索路由表, 在不支持策略路由时调用 */
static inline int fib_lookup(struct net *net, const struct flowi *flp,
			     struct fib_result *res)
{
	struct fib_table *table;

	/* 先在RT_TABLE_LOCAL路由表中查找 */
	table = fib_get_table(net, RT_TABLE_LOCAL);
	if (!table->tb_lookup(table, flp, res)) /* 调用fn_hash_lookup() */
		return 0;

	/* 找不到再从RT_TABLE_MAIN路由表中查找 */
	table = fib_get_table(net, RT_TABLE_MAIN);
	if (!table->tb_lookup(table, flp, res))
		return 0;
	return -ENETUNREACH; /* 找不到 */
}

#else /* CONFIG_IP_MULTIPLE_TABLES */
extern int __net_init fib4_rules_init(struct net *net);
extern void __net_exit fib4_rules_exit(struct net *net);

#ifdef CONFIG_NET_CLS_ROUTE
extern u32 fib_rules_tclass(struct fib_result *res);
#endif

extern int fib_lookup(struct net *n, struct flowi *flp, struct fib_result *res);

extern struct fib_table *fib_new_table(struct net *net, u32 id);
extern struct fib_table *fib_get_table(struct net *net, u32 id);

#endif /* CONFIG_IP_MULTIPLE_TABLES */

/* Exported by fib_frontend.c */
extern const struct nla_policy rtm_ipv4_policy[];
extern void		ip_fib_init(void);
extern int fib_validate_source(__be32 src, __be32 dst, u8 tos, int oif,
			       struct net_device *dev, __be32 *spec_dst,
			       u32 *itag, u32 mark);
extern void fib_select_default(struct net *net, const struct flowi *flp,
			       struct fib_result *res);

/* Exported by fib_semantics.c */
extern int ip_fib_check_default(__be32 gw, struct net_device *dev);
extern int fib_sync_down_dev(struct net_device *dev, int force);
extern int fib_sync_down_addr(struct net *net, __be32 local);
extern int fib_sync_up(struct net_device *dev);
extern __be32  __fib_res_prefsrc(struct fib_result *res);
extern void fib_select_multipath(const struct flowi *flp, struct fib_result *res);

/* Exported by fib_{hash|trie}.c */
extern void fib_hash_init(void);
extern struct fib_table *fib_hash_table(u32 id);

static inline void fib_combine_itag(u32 *itag, struct fib_result *res)
{
#ifdef CONFIG_NET_CLS_ROUTE
#ifdef CONFIG_IP_MULTIPLE_TABLES
	u32 rtag;
#endif
	*itag = FIB_RES_NH(*res).nh_tclassid<<16;
#ifdef CONFIG_IP_MULTIPLE_TABLES
	rtag = fib_rules_tclass(res);
	if (*itag == 0)
		*itag = (rtag<<16);
	*itag |= (rtag>>16);
#endif
#endif
}

extern void free_fib_info(struct fib_info *fi);

static inline void fib_info_put(struct fib_info *fi)
{
	if (atomic_dec_and_test(&fi->fib_clntref))
		free_fib_info(fi);
}

static inline void fib_res_put(struct fib_result *res)
{
	if (res->fi)
		fib_info_put(res->fi);
#ifdef CONFIG_IP_MULTIPLE_TABLES
	if (res->r)
		fib_rule_put(res->r);
#endif
}

#ifdef CONFIG_PROC_FS
extern int __net_init  fib_proc_init(struct net *net);
extern void __net_exit fib_proc_exit(struct net *net);
#else
static inline int fib_proc_init(struct net *net)
{
	return 0;
}
static inline void fib_proc_exit(struct net *net)
{
}
#endif

#endif  /* _NET_FIB_H */
