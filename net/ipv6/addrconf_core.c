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

	/* ȡ����һ���ֽ����жϵ�ַ���� */
	st = addr->s6_addr32[0];

	/* Consider all addresses with the first three bits different of
	   000 and 111 as unicasts.
	 */
	/* ���ǰ3λ��Ϊ000��111, ��ô����ȫ�򵥲���ַ */
	if ((st & htonl(0xE0000000)) != htonl(0x00000000) &&
	    (st & htonl(0xE0000000)) != htonl(0xE0000000))
		return (IPV6_ADDR_UNICAST | /* ������ַ */
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL)); /* ȫ��ɴ� */

	/* ǰ8λȫ��1(FF), ��Ϊ�ಥ��ַ */
	if ((st & htonl(0xFF000000)) == htonl(0xFF000000)) {
		/* multicast */
		/* addr-select 3.1 */
		return (IPV6_ADDR_MULTICAST | /* �ಥ��ַ */
			ipv6_addr_scope2type(IPV6_ADDR_MC_SCOPE(addr))); /* �ٸ��ݵڶ��ֽ�ȷ���ಥ��ַ���� */
	}

	/* ǰ10λ��1111 1110 10(FE80)��Ϊ��·���ص�ַ */
	if ((st & htonl(0xFFC00000)) == htonl(0xFE800000))
		return (IPV6_ADDR_LINKLOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));		/* addr-select 3.1 */

	/* ǰ10λ��1111 1110 11(FEC0)��Ϊվ�㱾�ص�ַ */
	if ((st & htonl(0xFFC00000)) == htonl(0xFEC00000))
		return (IPV6_ADDR_SITELOCAL | IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_SITELOCAL));		/* addr-select 3.1 */

	/* �ų����Ϻ�, ���ǰ7λ��1111 110(FC��FD)��Ҳ��ȫ�򵥲���ַ */
	if ((st & htonl(0xFE000000)) == htonl(0xFC000000))
		return (IPV6_ADDR_UNICAST |
			IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));			/* RFC 4193 */

	/* ���ǰ64λ��Ϊ0, ����Ϊδָ����ַ/�ػ���ַ/ipv4���ݵ�ַ/ipv4ӳ���ַ, �ٽ�һ���ж� */
	if ((addr->s6_addr32[0] | addr->s6_addr32[1]) == 0) {
		/* ���ǰ96λȫΪ0, ����Ϊ δָ����ַ/�ػ���ַ/ipv4���ݵ�ַ */
		if (addr->s6_addr32[2] == 0) {
			/* ȫ0Ϊδָ����ַ */
			if (addr->s6_addr32[3] == 0)
				return IPV6_ADDR_ANY;
			/* �������һλΪ1(::1/128)Ϊ�ػ���ַ */
			if (addr->s6_addr32[3] == htonl(0x00000001))
				return (IPV6_ADDR_LOOPBACK | IPV6_ADDR_UNICAST |
					IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_LINKLOCAL));	/* addr-select 3.4 */
			/* ǰ96λȫ0 ��Ϊipv4���ݵ�ַ(��32λ��ipv4��ַ),����д���Ѿ����� */
			return (IPV6_ADDR_COMPATv4 | IPV6_ADDR_UNICAST |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.3 */
		}
		
		/* ���ǰ64λΪ0,����32λΪ1,����ipv4ӳ���ַ(��::FFFF:w.x.y.z, �������32λΪipv4��ַ) */
		if (addr->s6_addr32[2] == htonl(0x0000ffff))
			return (IPV6_ADDR_MAPPED |
				IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.3 */
	}

	/* ������Ǳ�����ַ */
	return (IPV6_ADDR_RESERVED |
		IPV6_ADDR_SCOPE_TYPE(IPV6_ADDR_SCOPE_GLOBAL));	/* addr-select 3.4 */
}
EXPORT_SYMBOL(__ipv6_addr_type);

