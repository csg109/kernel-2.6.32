#ifndef _FIB_LOOKUP_H
#define _FIB_LOOKUP_H

#include <linux/types.h>
#include <linux/list.h>
#include <net/ip_fib.h>

struct fib_alias { /* 代表一条路由表项。每一条路由表项有各自的fib_alias
		    * 目的地址相同但其他配置参数不同的表项共享fib_node实例
		    */
	struct list_head	fa_list; /* 将共享同一个fib_node的所有fib_alias链接起来 */
	struct fib_info		*fa_info; /* 每个fib_alias与一个存储真正路由信息的fib_info相关联 */
	u8			fa_tos;	/* 路由的服务类型字段，为0时表示还没有配置TOS, 
					 * 所以在路由查找时任何值都能匹配 
					 */
	u8			fa_type; /* 路由表项的类型，有RTN_LOCAL/RTN_UNICAST等值 */
	u8			fa_scope; /* 路由表的作用范围 */
	u8			fa_state; /* 一些标志的位图，目前只有FA_S_ACCESSED */
#ifdef CONFIG_IP_FIB_TRIE
	struct rcu_head		rcu;
#endif
};

#define FA_S_ACCESSED	0x01 	/* 表示该表项已经被访问过 */

/* Exported by fib_semantics.c */
extern int fib_semantic_match(struct list_head *head,
			      const struct flowi *flp,
			      struct fib_result *res, int prefixlen);
extern void fib_release_info(struct fib_info *);
extern struct fib_info *fib_create_info(struct fib_config *cfg);
extern int fib_nh_match(struct fib_config *cfg, struct fib_info *fi);
extern int fib_dump_info(struct sk_buff *skb, u32 pid, u32 seq, int event,
			 u32 tb_id, u8 type, u8 scope, __be32 dst,
			 int dst_len, u8 tos, struct fib_info *fi,
			 unsigned int);
extern void rtmsg_fib(int event, __be32 key, struct fib_alias *fa,
		      int dst_len, u32 tb_id, struct nl_info *info,
		      unsigned int nlm_flags);
extern struct fib_alias *fib_find_alias(struct list_head *fah,
					u8 tos, u32 prio);
extern int fib_detect_death(struct fib_info *fi, int order,
			    struct fib_info **last_resort,
			    int *last_idx, int dflt);

static inline void fib_result_assign(struct fib_result *res,
				     struct fib_info *fi)
{
	if (res->fi != NULL)
		fib_info_put(res->fi);
	res->fi = fi;
	if (fi != NULL)
		atomic_inc(&fi->fib_clntref);
}

#endif /* _FIB_LOOKUP_H */
