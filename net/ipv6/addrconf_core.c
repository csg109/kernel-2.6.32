/*
 * IPv6 library code, needed by static components when full IPv6 support is
 * not configured or static.
 */

#include <net/ipv6.h>

#define IPV6_ADDR_SCOPE_TYPE(scope)	((scope) << 16)

static inline unsigned ipv6_addr_scope2type(unsigned scope)
{
	switch(scope) {
	case IPV6_ADDR_SCOPE_NODELOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_NODELOCAL) |
			IPV6_ADDR_LOOPBACK);
	case IPV6_ADDR_SCOPE_LINKLOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL) |
			IPV6_ADDR_LINKLOCAL);
	case IPV6_ADDR_SCOPE_SITELOCAL:
		return (IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL) |
			IPV6_ADDR_SITELOCAL);
	}
	return IPV6_ADDR_SCOPE_TYPE(scope);
}

int __ipv6_addr_type(const struct in6_addr *addr)
{
	__be32 st;

	/* 取出第一个字节来判断地址类型 */
	st = addr->s6_addr32[0];

	/* Consider all addresses with the first three bits different of
	   000 and 111 as unicasts.
	 */
	/* 如果前3位不为000或111, 那么就是全球单播地址 */
	if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
	    (st & htonl(0xE0000000)) != htonl(0xE0000000))
		return (IPV6_ADDR_UNICAST | /* 单播地址 */
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL)); /* 全球可达 */

	/* 前8位全是1(FF), 则为多播地址 */
	if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
		/* multicast */
		/* addr-select 3.1 */
		return (IPV6_ADDR_MULTICAST | /* 多播地址 */
			ipv6_addr_scope2type(IPV6_ADDR_MC_SCOPE(addr))); /* 再根据第二字节确定多播地址类型 */
	}

	/* 前10位是1111 1110 10(FE80)则为链路本地地址 */
	if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
		return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));		/* addr-select 3.1 */

	/* 前10位是1111 1110 11(FEC0)则为站点本地地址 */
	if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
		return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));		/* addr-select 3.1 */

	/* 排除以上后, 如果前7位是1111 110(FC和FD)则也是全球单播地址 */
	if ((st & htonl(0xFE000000)) == htonl(0xFC000000))
		return (IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));			/* RFC 4193 */

	/* 如果前64位都为0, 可能为未指定地址/回环地址/ipv4兼容地址/ipv4映射地址, 再进一步判断 */
	if ((addr->s6_addr32[0] | addr->s6_addr32[1]) == 0) {
		/* 如果前96位全为0, 可能为 未指定地址/回环地址/ipv4兼容地址 */
		if (addr->s6_addr32[2] == 0) {
			/* 全0为未指定地址 */
			if (addr->s6_addr32[3] == 0)
				return IPV6_ADDR_ANY;
			/* 仅有最后一位为1(::1/128)为回环地址 */
			if (addr->s6_addr32[3] == htonl(0x00000001))
				return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
					IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));	/* addr-select 3.4 */
			/* 前96位全0 则为ipv4兼容地址(后32位是ipv4地址),这种写法已经废弃 */
			return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.3 */
		}
		
		/* 如果前64位为0,接着32位为1,则是ipv4映射地址(即::FFFF:w.x.y.z, 其中最后32位为ipv4地址) */
		if (addr->s6_addr32[2] == htonl(0x0000ffff))
			return (IPV6_ADDR_MAPPED |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.3 */
	}

	/* 否则就是保留地址 */
	return (IPV6_ADDR_RESERVED |
		IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.4 */
}
EXPORT_SYMBOL(__ipv6_addr_type);

