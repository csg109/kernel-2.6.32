/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *
 * Fixes:
 *		Alan Cox	:	Numerous verify_area() calls
 *		Alan Cox	:	Set the ACK bit on a reset
 *		Alan Cox	:	Stopped it crashing if it closed while
 *					sk->inuse=1 and was trying to connect
 *					(tcp_err()).
 *		Alan Cox	:	All icmp error handling was broken
 *					pointers passed where wrong and the
 *					socket was looked up backwards. Nobody
 *					tested any icmp error code obviously.
 *		Alan Cox	:	tcp_err() now handled properly. It
 *					wakes people on errors. poll
 *					behaves and the icmp error race
 *					has gone by moving it into sock.c
 *		Alan Cox	:	tcp_send_reset() fixed to work for
 *					everything not just packets for
 *					unknown sockets.
 *		Alan Cox	:	tcp option processing.
 *		Alan Cox	:	Reset tweaked (still not 100%) [Had
 *					syn rule wrong]
 *		Herp Rosmanith  :	More reset fixes
 *		Alan Cox	:	No longer acks invalid rst frames.
 *					Acking any kind of RST is right out.
 *		Alan Cox	:	Sets an ignore me flag on an rst
 *					receive otherwise odd bits of prattle
 *					escape still
 *		Alan Cox	:	Fixed another acking RST frame bug.
 *					Should stop LAN workplace lockups.
 *		Alan Cox	: 	Some tidyups using the new skb list
 *					facilities
 *		Alan Cox	:	sk->keepopen now seems to work
 *		Alan Cox	:	Pulls options out correctly on accepts
 *		Alan Cox	:	Fixed assorted sk->rqueue->next errors
 *		Alan Cox	:	PSH doesn't end a TCP read. Switched a
 *					bit to skb ops.
 *		Alan Cox	:	Tidied tcp_data to avoid a potential
 *					nasty.
 *		Alan Cox	:	Added some better commenting, as the
 *					tcp is hard to follow
 *		Alan Cox	:	Removed incorrect check for 20 * psh
 *	Michael O'Reilly	:	ack < copied bug fix.
 *	Johannes Stille		:	Misc tcp fixes (not all in yet).
 *		Alan Cox	:	FIN with no memory -> CRASH
 *		Alan Cox	:	Added socket option proto entries.
 *					Also added awareness of them to accept.
 *		Alan Cox	:	Added TCP options (SOL_TCP)
 *		Alan Cox	:	Switched wakeup calls to callbacks,
 *					so the kernel can layer network
 *					sockets.
 *		Alan Cox	:	Use ip_tos/ip_ttl settings.
 *		Alan Cox	:	Handle FIN (more) properly (we hope).
 *		Alan Cox	:	RST frames sent on unsynchronised
 *					state ack error.
 *		Alan Cox	:	Put in missing check for SYN bit.
 *		Alan Cox	:	Added tcp_select_window() aka NET2E
 *					window non shrink trick.
 *		Alan Cox	:	Added a couple of small NET2E timer
 *					fixes
 *		Charles Hedrick :	TCP fixes
 *		Toomas Tamm	:	TCP window fixes
 *		Alan Cox	:	Small URG fix to rlogin ^C ack fight
 *		Charles Hedrick	:	Rewrote most of it to actually work
 *		Linus		:	Rewrote tcp_read() and URG handling
 *					completely
 *		Gerhard Koerting:	Fixed some missing timer handling
 *		Matthew Dillon  :	Reworked TCP machine states as per RFC
 *		Gerhard Koerting:	PC/TCP workarounds
 *		Adam Caldwell	:	Assorted timer/timing errors
 *		Matthew Dillon	:	Fixed another RST bug
 *		Alan Cox	:	Move to kernel side addressing changes.
 *		Alan Cox	:	Beginning work on TCP fastpathing
 *					(not yet usable)
 *		Arnt Gulbrandsen:	Turbocharged tcp_check() routine.
 *		Alan Cox	:	TCP fast path debugging
 *		Alan Cox	:	Window clamping
 *		Michael Riepe	:	Bug in tcp_check()
 *		Matt Dillon	:	More TCP improvements and RST bug fixes
 *		Matt Dillon	:	Yet more small nasties remove from the
 *					TCP code (Be very nice to this man if
 *					tcp finally works 100%) 8)
 *		Alan Cox	:	BSD accept semantics.
 *		Alan Cox	:	Reset on closedown bug.
 *	Peter De Schrijver	:	ENOTCONN check missing in tcp_sendto().
 *		Michael Pall	:	Handle poll() after URG properly in
 *					all cases.
 *		Michael Pall	:	Undo the last fix in tcp_read_urg()
 *					(multi URG PUSH broke rlogin).
 *		Michael Pall	:	Fix the multi URG PUSH problem in
 *					tcp_readable(), poll() after URG
 *					works now.
 *		Michael Pall	:	recv(...,MSG_OOB) never blocks in the
 *					BSD api.
 *		Alan Cox	:	Changed the semantics of sk->socket to
 *					fix a race and a signal problem with
 *					accept() and async I/O.
 *		Alan Cox	:	Relaxed the rules on tcp_sendto().
 *		Yury Shevchuk	:	Really fixed accept() blocking problem.
 *		Craig I. Hagan  :	Allow for BSD compatible TIME_WAIT for
 *					clients/servers which listen in on
 *					fixed ports.
 *		Alan Cox	:	Cleaned the above up and shrank it to
 *					a sensible code size.
 *		Alan Cox	:	Self connect lockup fix.
 *		Alan Cox	:	No connect to multicast.
 *		Ross Biro	:	Close unaccepted children on master
 *					socket close.
 *		Alan Cox	:	Reset tracing code.
 *		Alan Cox	:	Spurious resets on shutdown.
 *		Alan Cox	:	Giant 15 minute/60 second timer error
 *		Alan Cox	:	Small whoops in polling before an
 *					accept.
 *		Alan Cox	:	Kept the state trace facility since
 *					it's handy for debugging.
 *		Alan Cox	:	More reset handler fixes.
 *		Alan Cox	:	Started rewriting the code based on
 *					the RFC's for other useful protocol
 *					references see: Comer, KA9Q NOS, and
 *					for a reference on the difference
 *					between specifications and how BSD
 *					works see the 4.4lite source.
 *		A.N.Kuznetsov	:	Don't time wait on completion of tidy
 *					close.
 *		Linus Torvalds	:	Fin/Shutdown & copied_seq changes.
 *		Linus Torvalds	:	Fixed BSD port reuse to work first syn
 *		Alan Cox	:	Reimplemented timers as per the RFC
 *					and using multiple timers for sanity.
 *		Alan Cox	:	Small bug fixes, and a lot of new
 *					comments.
 *		Alan Cox	:	Fixed dual reader crash by locking
 *					the buffers (much like datagram.c)
 *		Alan Cox	:	Fixed stuck sockets in probe. A probe
 *					now gets fed up of retrying without
 *					(even a no space) answer.
 *		Alan Cox	:	Extracted closing code better
 *		Alan Cox	:	Fixed the closing state machine to
 *					resemble the RFC.
 *		Alan Cox	:	More 'per spec' fixes.
 *		Jorge Cwik	:	Even faster checksumming.
 *		Alan Cox	:	tcp_data() doesn't ack illegal PSH
 *					only frames. At least one pc tcp stack
 *					generates them.
 *		Alan Cox	:	Cache last socket.
 *		Alan Cox	:	Per route irtt.
 *		Matt Day	:	poll()->select() match BSD precisely on error
 *		Alan Cox	:	New buffers
 *		Marc Tamsky	:	Various sk->prot->retransmits and
 *					sk->retransmits misupdating fixed.
 *					Fixed tcp_write_timeout: stuck close,
 *					and TCP syn retries gets used now.
 *		Mark Yarvis	:	In tcp_read_wakeup(), don't send an
 *					ack if state is TCP_CLOSED.
 *		Alan Cox	:	Look up device on a retransmit - routes may
 *					change. Doesn't yet cope with MSS shrink right
 *					but it's a start!
 *		Marc Tamsky	:	Closing in closing fixes.
 *		Mike Shaver	:	RFC1122 verifications.
 *		Alan Cox	:	rcv_saddr errors.
 *		Alan Cox	:	Block double connect().
 *		Alan Cox	:	Small hooks for enSKIP.
 *		Alexey Kuznetsov:	Path MTU discovery.
 *		Alan Cox	:	Support soft errors.
 *		Alan Cox	:	Fix MTU discovery pathological case
 *					when the remote claims no mtu!
 *		Marc Tamsky	:	TCP_CLOSE fix.
 *		Colin (G3TNE)	:	Send a reset on syn ack replies in
 *					window but wrong (fixes NT lpd problems)
 *		Pedro Roque	:	Better TCP window handling, delayed ack.
 *		Joerg Reuter	:	No modification of locked buffers in
 *					tcp_do_retransmit()
 *		Eric Schenk	:	Changed receiver side silly window
 *					avoidance algorithm to BSD style
 *					algorithm. This doubles throughput
 *					against machines running Solaris,
 *					and seems to result in general
 *					improvement.
 *	Stefan Magdalinski	:	adjusted tcp_readable() to fix FIONREAD
 *	Willy Konynenberg	:	Transparent proxying support.
 *	Mike McLagan		:	Routing by source
 *		Keith Owens	:	Do proper merging with partial SKB's in
 *					tcp_do_sendmsg to avoid burstiness.
 *		Eric Schenk	:	Fix fast close down bug with
 *					shutdown() followed by close().
 *		Andi Kleen 	:	Make poll agree with SIGIO
 *	Salvatore Sanfilippo	:	Support SO_LINGER with linger == 1 and
 *					lingertime == 0 (RFC 793 ABORT Call)
 *	Hirokazu Takahashi	:	Use copy_from_user() instead of
 *					csum_and_copy_from_user() if possible.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or(at your option) any later version.
 *
 * Description of States:
 *
 *	TCP_SYN_SENT		sent a connection request, waiting for ack
 *
 *	TCP_SYN_RECV		received a connection request, sent ack,
 *				waiting for final ack in three-way handshake.
 *
 *	TCP_ESTABLISHED		connection established
 *
 *	TCP_FIN_WAIT1		our side has shutdown, waiting to complete
 *				transmission of remaining buffered data
 *
 *	TCP_FIN_WAIT2		all buffered data sent, waiting for remote
 *				to shutdown
 *
 *	TCP_CLOSING		both sides have shutdown but we still have
 *				data we have to finish sending
 *
 *	TCP_TIME_WAIT		timeout to catch resent junk before entering
 *				closed, can only be entered from FIN_WAIT2
 *				or CLOSING.  Required because the other end
 *				may not have gotten our last ACK causing it
 *				to retransmit the data packet (which we ignore)
 *
 *	TCP_CLOSE_WAIT		remote side has shutdown and is waiting for
 *				us to finish writing our data and to shutdown
 *				(we have to close() to move on to LAST_ACK)
 *
 *	TCP_LAST_ACK		out side has shutdown after remote has
 *				shutdown.  There may still be data in our
 *				buffer that we have to finish sending
 *
 *	TCP_CLOSE		socket is finished
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/skbuff.h>
#include <linux/scatterlist.h>
#include <linux/splice.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/random.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/cache.h>
#include <linux/err.h>
#include <linux/crypto.h>

#include <net/icmp.h>
#include <net/tcp.h>
#include <net/xfrm.h>
#include <net/ip.h>
#include <net/netdma.h>
#include <net/sock.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

int sysctl_tcp_fin_timeout __read_mostly = TCP_FIN_TIMEOUT;

struct percpu_counter tcp_orphan_count;
EXPORT_SYMBOL_GPL(tcp_orphan_count);

int sysctl_tcp_mem[3] __read_mostly;
int sysctl_tcp_wmem[3] __read_mostly;
int sysctl_tcp_rmem[3] __read_mostly;

EXPORT_SYMBOL(sysctl_tcp_mem);
EXPORT_SYMBOL(sysctl_tcp_rmem);
EXPORT_SYMBOL(sysctl_tcp_wmem);

atomic_t tcp_memory_allocated;	/* Current allocated memory. */
EXPORT_SYMBOL(tcp_memory_allocated);

/*
 * Current number of TCP sockets.
 */
struct percpu_counter tcp_sockets_allocated;
EXPORT_SYMBOL(tcp_sockets_allocated);

/*
 * TCP splice context
 */
struct tcp_splice_state {
	struct pipe_inode_info *pipe;
	size_t len;
	unsigned int flags;
};

/*
 * Pressure flag: try to collapse.
 * Technical note: it is used by multiple contexts non atomically.
 * All the __sk_mem_schedule() is of this nature: accounting
 * is strict, actions are advisory and have some latency.
 */
int tcp_memory_pressure __read_mostly;

EXPORT_SYMBOL(tcp_memory_pressure);

void tcp_enter_memory_pressure(struct sock *sk)
{
	if (!tcp_memory_pressure) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPMEMORYPRESSURES);
		tcp_memory_pressure = 1; /* 设置压力标志 */
	}
}

EXPORT_SYMBOL(tcp_enter_memory_pressure);

/* Convert seconds to retransmits based on initial and max timeout */
static u8 secs_to_retrans(int seconds, int timeout, int rto_max)
{
	u8 res = 0;

	if (seconds > 0) {
		int period = timeout;

		res = 1;
		while (seconds > period && res < 255) {
			res++;
			timeout <<= 1;
			if (timeout > rto_max)
				timeout = rto_max;
			period += timeout;
		}
	}
	return res;
}

/* Convert retransmits to seconds based on initial and max timeout */
static int retrans_to_secs(u8 retrans, int timeout, int rto_max)
{
	int period = 0;

	if (retrans > 0) {
		period = timeout;
		while (--retrans) {
			timeout <<= 1;
			if (timeout > rto_max)
				timeout = rto_max;
			period += timeout;
		}
	}
	return period;
}

/*
 *	Wait for a TCP event.
 *
 *	Note that we don't need to lock the socket, as the upper poll layers
 *	take care of normal races (between the test and the event) and we don't
 *	go look at any of the socket buffers directly.
 */
unsigned int tcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask;
	struct sock *sk = sock->sk;
	struct tcp_sock *tp = tcp_sk(sk);

	sock_poll_wait(file, sk->sk_sleep, wait);
	if (sk->sk_state == TCP_LISTEN)
		return inet_csk_listen_poll(sk);

	/* Socket is not locked. We are protected from async events
	 * by poll logic and correct handling of state changes
	 * made by other threads is impossible in any case.
	 */

	mask = 0;
	if (sk->sk_err)
		mask = POLLERR;

	/*
	 * POLLHUP is certainly not done right. But poll() doesn't
	 * have a notion of HUP in just one direction, and for a
	 * socket the read side is more interesting.
	 *
	 * Some poll() documentation says that POLLHUP is incompatible
	 * with the POLLOUT/POLLWR flags, so somebody should check this
	 * all. But careful, it tends to be safer to return too many
	 * bits than too few, and you can easily break real applications
	 * if you don't tell them that something has hung up!
	 *
	 * Check-me.
	 *
	 * Check number 1. POLLHUP is _UNMASKABLE_ event (see UNIX98 and
	 * our fs/select.c). It means that after we received EOF,
	 * poll always returns immediately, making impossible poll() on write()
	 * in state CLOSE_WAIT. One solution is evident --- to set POLLHUP
	 * if and only if shutdown has been made in both directions.
	 * Actually, it is interesting to look how Solaris and DUX
	 * solve this dilemma. I would prefer, if POLLHUP were maskable,
	 * then we could set it on SND_SHUTDOWN. BTW examples given
	 * in Stevens' books assume exactly this behaviour, it explains
	 * why POLLHUP is incompatible with POLLOUT.	--ANK
	 *
	 * NOTE. Check for TCP_CLOSE is added. The goal is to prevent
	 * blocking on fresh not-connected or disconnected socket. --ANK
	 */
	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		mask |= POLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= POLLIN | POLLRDNORM | POLLRDHUP;

	/* Connected? */
	if ((1 << sk->sk_state) & ~(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		int target = sock_rcvlowat(sk, 0, INT_MAX);

		if (tp->urg_seq == tp->copied_seq &&
		    !sock_flag(sk, SOCK_URGINLINE) &&
		    tp->urg_data)
			target++;

		/* Potential race condition. If read of tp below will
		 * escape above sk->sk_state, we can be illegally awaken
		 * in SYN_* states. */
		if (tp->rcv_nxt - tp->copied_seq >= target)
			mask |= POLLIN | POLLRDNORM;

		if (!(sk->sk_shutdown & SEND_SHUTDOWN)) {
			if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk)) {
				mask |= POLLOUT | POLLWRNORM;
			} else {  /* send SIGIO later */
				set_bit(SOCK_ASYNC_NOSPACE,
					&sk->sk_socket->flags);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

				/* Race breaker. If space is freed after
				 * wspace test but before the flags are set,
				 * IO signal will be lost.
				 */
				if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk))
					mask |= POLLOUT | POLLWRNORM;
			}
		}

		if (tp->urg_data & TCP_URG_VALID)
			mask |= POLLPRI;
	}
	return mask;
}

int tcp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int answ;

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !tp->urg_data ||
			 before(tp->urg_seq, tp->copied_seq) ||
			 !before(tp->urg_seq, tp->rcv_nxt)) {
			struct sk_buff *skb;

			answ = tp->rcv_nxt - tp->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			skb = skb_peek_tail(&sk->sk_receive_queue);
			if (answ && skb)
				answ -= tcp_hdr(skb)->fin;
		} else
			answ = tp->urg_seq - tp->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:
		answ = tp->urg_data && tp->urg_seq == tp->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = tp->write_seq - tp->snd_una;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return put_user(answ, (int __user *)arg);
}

static inline void tcp_mark_push(struct tcp_sock *tp, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
	tp->pushed_seq = tp->write_seq;
}

static inline int forced_push(struct tcp_sock *tp)
{
	return after(tp->write_seq, tp->pushed_seq + (tp->max_window >> 1));
}

static inline void skb_entail(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	skb->csum    = 0;
	tcb->seq     = tcb->end_seq = tp->write_seq;
	tcb->flags   = TCPCB_FLAG_ACK;
	tcb->sacked  = 0;
	skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb); /* 把skb加入sk_write_queue发送队列的尾部 */
	sk->sk_wmem_queued += skb->truesize; /* 增加已分配的缓存大小 */
	sk_mem_charge(sk, skb->truesize); /* 这里调整sk_forward_alloc的大小，也就是预分配buf的大小(减小) */
	if (tp->nonagle & TCP_NAGLE_PUSH)
		tp->nonagle &= ~TCP_NAGLE_PUSH;
}

static inline void tcp_mark_urg(struct tcp_sock *tp, int flags,
				struct sk_buff *skb)
{
	if (flags & MSG_OOB)
		tp->snd_up = tp->write_seq;
}

static inline void tcp_push(struct sock *sk, int flags, int mss_now,
			    int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_send_head(sk)) {
		struct sk_buff *skb = tcp_write_queue_tail(sk);
		if (!(flags & MSG_MORE) || forced_push(tp))
			tcp_mark_push(tp, skb);
		tcp_mark_urg(tp, flags, skb);
		__tcp_push_pending_frames(sk, mss_now,
					  (flags & MSG_MORE) ? TCP_NAGLE_CORK : nonagle);
	}
}

static int tcp_splice_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
				unsigned int offset, size_t len)
{
	struct tcp_splice_state *tss = rd_desc->arg.data;
	int ret;

	ret = skb_splice_bits(skb, offset, tss->pipe, min(rd_desc->count, len),
			      tss->flags);
	if (ret > 0)
		rd_desc->count -= ret;
	return ret;
}

static int __tcp_splice_read(struct sock *sk, struct tcp_splice_state *tss)
{
	/* Store TCP splice context information in read_descriptor_t. */
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count	  = tss->len,
	};

	return tcp_read_sock(sk, &rd_desc, tcp_splice_data_recv);
}

/**
 *  tcp_splice_read - splice data from TCP socket to a pipe
 * @sock:	socket to splice from
 * @ppos:	position (not valid)
 * @pipe:	pipe to splice to
 * @len:	number of bytes to splice
 * @flags:	splice modifier flags
 *
 * Description:
 *    Will read pages from given socket and fill them into a pipe.
 *
 **/
ssize_t tcp_splice_read(struct socket *sock, loff_t *ppos,
			struct pipe_inode_info *pipe, size_t len,
			unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct tcp_splice_state tss = {
		.pipe = pipe,
		.len = len,
		.flags = flags,
	};
	long timeo;
	ssize_t spliced;
	int ret;

	/*
	 * We can't seek on a socket input
	 */
	if (unlikely(*ppos))
		return -ESPIPE;

	ret = spliced = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);
	while (tss.len) {
		ret = __tcp_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				if (!sock_flag(sk, SOCK_DONE))
					ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			sk_wait_data(sk, &timeo);
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		tss.len -= ret;
		spliced += ret;

		if (!timeo)
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);

	if (spliced)
		return spliced;

	return ret;
}

struct sk_buff *sk_stream_alloc_skb(struct sock *sk, int size, gfp_t gfp)
{
	struct sk_buff *skb;

	/* The TCP header must be at least 32-bit aligned.  */
	size = ALIGN(size, 4); /* 对齐4字节 */

	skb = alloc_skb_fclone(size + sk->sk_prot->max_header, gfp); /* 分配skb */
	if (skb) {
		/* 判断内存的压力情况, 可以分配则返回skb */
		if (sk_wmem_schedule(sk, skb->truesize)) {
			/*
			 * Make sure that we have exactly size bytes
			 * available to the caller, no more, no less.
			 */
			skb_reserve(skb, skb_tailroom(skb) - size); /* 把剩余空间预留给首部 */
			return skb;
		}
		__kfree_skb(skb);
	} else { /* 进入内存压力模式并调整sndbuf */
		sk->sk_prot->enter_memory_pressure(sk); /* tcp_enter_memory_pressure(), 设置标志进入TCP memory pressure zone */
		sk_stream_moderate_sndbuf(sk); /* 减小sndbuf */
	}
	return NULL;
}

static unsigned int tcp_xmit_size_goal(struct sock *sk, u32 mss_now,
				       int large_allowed)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 xmit_size_goal, old_size_goal;

	xmit_size_goal = mss_now;

	if (large_allowed && sk_can_gso(sk)) {
		xmit_size_goal = ((sk->sk_gso_max_size - 1) -
				  inet_csk(sk)->icsk_af_ops->net_header_len -
				  inet_csk(sk)->icsk_ext_hdr_len -
				  tp->tcp_header_len);

		xmit_size_goal = tcp_bound_to_half_wnd(tp, xmit_size_goal);

		/* We try hard to avoid divides here */
		old_size_goal = tp->xmit_size_goal_segs * mss_now;

		if (likely(old_size_goal <= xmit_size_goal &&
			   old_size_goal + mss_now > xmit_size_goal)) {
			xmit_size_goal = old_size_goal;
		} else {
			tp->xmit_size_goal_segs = xmit_size_goal / mss_now;
			xmit_size_goal = tp->xmit_size_goal_segs * mss_now;
		}
	}

	return max(xmit_size_goal, mss_now);
}

static int tcp_send_mss(struct sock *sk, int *size_goal, int flags)
{
	int mss_now;

	mss_now = tcp_current_mss(sk);
	*size_goal = tcp_xmit_size_goal(sk, mss_now, !(flags & MSG_OOB));

	return mss_now;
}

static ssize_t do_tcp_sendpages(struct sock *sk, struct page **pages, int poffset,
			 size_t psize, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now, size_goal;
	int err;
	ssize_t copied;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = tcp_send_mss(sk, &size_goal, flags);
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	while (psize > 0) {
		struct sk_buff *skb = tcp_write_queue_tail(sk);
		struct page *page = pages[poffset / PAGE_SIZE];
		int copy, i, can_coalesce;
		int offset = poffset % PAGE_SIZE;
		int size = min_t(size_t, psize, PAGE_SIZE - offset);

		if (!tcp_send_head(sk) || (copy = size_goal - skb->len) <= 0) {
new_segment:
			if (!sk_stream_memory_free(sk))
				goto wait_for_sndbuf;

			skb = sk_stream_alloc_skb(sk, 0, sk->sk_allocation);
			if (!skb)
				goto wait_for_memory;

			skb_entail(sk, skb);
			copy = size_goal;
		}

		if (copy > size)
			copy = size;

		i = skb_shinfo(skb)->nr_frags;
		can_coalesce = skb_can_coalesce(skb, i, page, offset);
		if (!can_coalesce && i >= MAX_SKB_FRAGS) {
			tcp_mark_push(tp, skb);
			goto new_segment;
		}
		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		if (can_coalesce) {
			skb_shinfo(skb)->frags[i - 1].size += copy;
		} else {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, copy);
		}

		skb->len += copy;
		skb->data_len += copy;
		skb->truesize += copy;
		sk->sk_wmem_queued += copy;
		sk_mem_charge(sk, copy);
		skb->ip_summed = CHECKSUM_PARTIAL;
		tp->write_seq += copy;
		TCP_SKB_CB(skb)->end_seq += copy;
		skb_shinfo(skb)->gso_segs = 0;

		if (!copied)
			TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

		copied += copy;
		poffset += copy;
		if (!(psize -= copy))
			goto out;

		if (skb->len < size_goal || (flags & MSG_OOB))
			continue;

		if (forced_push(tp)) {
			tcp_mark_push(tp, skb);
			__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
		} else if (skb == tcp_send_head(sk))
			tcp_push_one(sk, mss_now);
		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		if (copied)
			tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

		if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
			goto do_error;

		mss_now = tcp_send_mss(sk, &size_goal, flags);
	}

out:
	if (copied)
		tcp_push(sk, flags, mss_now, tp->nonagle);
	return copied;

do_error:
	if (copied)
		goto out;
out_err:
	return sk_stream_error(sk, flags, err);
}

ssize_t tcp_sendpage(struct socket *sock, struct page *page, int offset,
		     size_t size, int flags)
{
	ssize_t res;
	struct sock *sk = sock->sk;

	if (!(sk->sk_route_caps & NETIF_F_SG) ||
	    !(sk->sk_route_caps & NETIF_F_ALL_CSUM))
		return sock_no_sendpage(sock, page, offset, size, flags);

	lock_sock(sk);
	TCP_CHECK_TIMER(sk);
	res = do_tcp_sendpages(sk, &page, offset, size, flags);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return res;
}

#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)

static inline int select_size(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int tmp = tp->mss_cache;

	/* 判断是否使用scatter-gather */
	if (sk->sk_route_caps & NETIF_F_SG) {
		if (sk_can_gso(sk))
			tmp = 0;
		else {
			int pgbreak = SKB_MAX_HEAD(MAX_TCP_HEADER);

			if (tmp >= pgbreak &&
			    tmp <= pgbreak + (MAX_SKB_FRAGS - 1) * PAGE_SIZE)
				tmp = pgbreak;
		}
	}

	return tmp;
}

int tcp_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		size_t size)
{
	struct sock *sk = sock->sk;
	struct iovec *iov;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now, size_goal;
	int err, copied;
	long timeo;

	lock_sock(sk); /* 持有sock,可能睡眠等待其他进程退出 */
	TCP_CHECK_TIMER(sk);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = tcp_send_mss(sk, &size_goal, flags);

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto out_err;

	while (--iovlen >= 0) {
		int seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;

		while (seglen > 0) {
			int copy = 0;
			int max = size_goal; /* 单个skb的最大数据长度，如果使用了GSO，长度为MSS的整数倍 */

			skb = tcp_write_queue_tail(sk); /* 发送队列的最后一个skb */
			if (tcp_send_head(sk)) { /* 还有未发送的数据，说明该skb还未发送 */
				if (skb->ip_summed == CHECKSUM_NONE) /* 如果网卡不支持检验和计算，那么skb的最大长度为MSS，即不能使用GSO */
					max = mss_now;
				copy = max - skb->len; /* 此skb可追加的数据长度 */
			}

			if (copy <= 0) { /* 需要使用新的skb来装数据 */
new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				/* 判断是否还有空间来供我们分配，如果没有则跳到wait_for_sndbuf来等待buf的释放 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;

				/*
				 * 申请一个skb，其线性数据区的大小为：
				 * 通过select_size()得到的线性数据区中TCP负荷的大小 + 最大的协议头长度。
				 * 如果申请skb失败了，或者虽然申请skb成功，但是从系统层面判断此次申请不合法，
				 * 那么就进入睡眠，等待内存
				 */
				skb = sk_stream_alloc_skb(sk, select_size(sk),
						sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				/* 如果网卡支持校验和的计算，那么由硬件计算报头和首部的校验和 */
				if (sk->sk_route_caps & NETIF_F_ALL_CSUM)
					skb->ip_summed = CHECKSUM_PARTIAL;

				skb_entail(sk, skb); /* 把skb加入发送队列并调整已分配和预分配的缓存大小 */
				copy = size_goal;
				max = size_goal;
			}

			/* Try to append data to the end of skb. */
			/* 本次可拷贝的数据量不能超过数据块的长度 */
			if (copy > seglen)
				copy = seglen;

			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) { /* 如果skb的线性数据区还有剩余空间，就先复制到线性数据区 */
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);
				if ((err = skb_add_data(skb, from, copy)) != 0) /* 拷贝数据 */
					goto do_fault;
			} else { /* 如果skb的线性数据区已经用完了，那么就使用分页区 */
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TCP_PAGE(sk);
				int off = TCP_OFF(sk);

				/* 如果之前的分片还有空间，那么把数据继续加到原来页上 */
				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == MAX_SKB_FRAGS ||
					   (!i &&
					   !(sk->sk_route_caps & NETIF_F_SG))) {
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					tcp_mark_push(tp, skb); /* 加上PSH标记 */
					goto new_segment;
				} else if (page) {
					/* 如果该分页的剩余空间已被用掉, 那么后续要申请新页了 */
					if (off == PAGE_SIZE) {
						put_page(page);
						TCP_PAGE(sk) = page = NULL;
						off = 0;
					}
				} else
					off = 0;

				/* 拷贝大小不能超过页剩余大小 */
				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				/* 判断内存压力 */
				if (!sk_wmem_schedule(sk, copy))
					goto wait_for_memory;

				/* page为空说明需要分配一个新页 */
				if (!page) {
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))
						goto wait_for_memory;
				}

				/* Time to copy data. We are close to
				 * the end! */
				/* 把数据拷贝到page中, 需要的话计算数据checksum */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (err) { /* 拷贝失败的话先把新的页给sk防止泄漏 */
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				/* 数据直接加到原来分页上后，只需要调整分页的数据长度 */
				if (merge) {
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;
				} else {
					/* 这里将page与skb的分片关联 */
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TCP_PAGE(sk)) {
						get_page(page);
					/* 如果该分页还有空间则记录到sk->sk_sndmsg_page,之后数据可以继续追加 */
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TCP_PAGE(sk) = page;
					}
				}

				TCP_OFF(sk) = off + copy;
			}

			if (!copied)
				TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

			tp->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			skb_shinfo(skb)->gso_segs = 0;

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < max || (flags & MSG_OOB))
				continue;

			if (forced_push(tp)) {
				tcp_mark_push(tp, skb);
				__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);
			} else if (skb == tcp_send_head(sk))
				tcp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			/* 设置写缓存空间不够用的标志, 收到确认时判断有这个标志后调用tcp_new_space()增加写缓存 */
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags); 
wait_for_memory:
			if (copied)
				tcp_push(sk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = tcp_send_mss(sk, &size_goal, flags);
		}
	}

out:
	if (copied)
		tcp_push(sk, flags, mss_now, tp->nonagle);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		tcp_unlink_write_queue(skb, sk);
		/* It is the one place in all of TCP, except connection
		 * reset, where we can be unlinking the send_head.
		 */
		tcp_check_send_head(sk, skb);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;
}

/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int tcp_recv_urg(struct sock *sk, struct msghdr *msg, int len, int flags)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !tp->urg_data ||
	    tp->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (tp->urg_data & TCP_URG_VALID) {
		int err = 0;
		char c = tp->urg_data;

		if (!(flags & MSG_PEEK))
			tp->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

/* Clean up the receive buffer for full frames taken by the user,
 * then send an ACK if necessary.  COPIED is the number of bytes
 * tcp_recvmsg has given to the user so far, it speeds up the
 * calculation of whether or not we must ACK for the sake of
 * a window update.
 */
void tcp_cleanup_rbuf(struct sock *sk, int copied)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int time_to_ack = 0;

#if TCP_DEBUG
	struct sk_buff *skb = skb_peek(&sk->sk_receive_queue); /* 获取接收队列的头一个数据段 */
	/* 这里检查在发送队列中，已复制到用户空间的数据段是否被清理了 */
	WARN(skb && !before(tp->copied_seq, TCP_SKB_CB(skb)->end_seq),
	     KERN_INFO "cleanup rbuf bug: copied %X seq %X rcvnxt %X\n",
	     tp->copied_seq, TCP_SKB_CB(skb)->end_seq, tp->rcv_nxt);
#endif

	/* 如果现在有ACK需要发送，满足以下条件之一则可以立即发送 */
	if (inet_csk_ack_scheduled(sk)) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		   /* Delayed ACKs frequently hit locked sockets during bulk
		    * receive. */
		/* 如果现在有ACK需要发送，满足以下条件之一，就可以立即发送：
		 * 1. icsk->icsk_ack.blocked为1，之前有Delayed ACK被用户进程阻塞了。
		 * 2. 接收缓冲区中有一个以上的全尺寸数据段仍然是NOT ACKed (所以经常是收到2个全尺寸段后发送ACK)
		 * 3. 本次复制到用户空间的数据量大于0，且满足以下条件之一：
		 *     3.1 设置了ICSK_ACK_PUSHED2标志
		 *     3.2 设置了ICSK_ACK_PUSHED标志，且处于快速确认模式中
		 */
		if (icsk->icsk_ack.blocked ||
		    /* Once-per-two-segments ACK was not sent by tcp_input.c */
		    tp->rcv_nxt - tp->rcv_wup > icsk->icsk_ack.rcv_mss ||
		    /*
		     * If this read emptied read buffer, we send ACK, if
		     * connection is not bidirectional, user drained
		     * receive buffer and there was a small segment
		     * in queue.
		     */
		    (copied > 0 &&
		     ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED2) ||
		      ((icsk->icsk_ack.pending & ICSK_ACK_PUSHED) &&
		       !icsk->icsk_ack.pingpong)) &&
		      !atomic_read(&sk->sk_rmem_alloc)))
			time_to_ack = 1;
	}

	/* We send an ACK if we can now advertise a non-zero window
	 * which has been raised "significantly".
	 *
	 * Even if window raised up to infinity, do not send window open ACK
	 * in states, where we will not receive more. It is useless.
	 */
	/* 如果原来没有ACK需要发送，但是现在的接收窗口显著增大了，也需要立即发送ACK通知对端。
	 * 这里的显著增大是指：新的接收窗口大小不为0，且比原来接收窗口的剩余量增大了一倍
	 */
	if (copied > 0 && !time_to_ack && !(sk->sk_shutdown & RCV_SHUTDOWN)) {
		__u32 rcv_window_now = tcp_receive_window(tp); /* 当前接收窗口的剩余量 */

		/* Optimize, __tcp_select_window() is not cheap. */
		if (2*rcv_window_now <= tp->window_clamp) { /* 如果当前接收窗口的剩余量小于最大值的一半 */
			/* 根据剩余的接收缓存，计算新的接收窗口的大小。 
			 * 因为这次复制，很可能空出不少接收缓存，所以新的接收窗口也会相应增大
			 */
			__u32 new_window = __tcp_select_window(sk);

			/* Send ACK now, if this read freed lots of space
			 * in our buffer. Certainly, new_window is new window.
			 * We can advertise it now, if it is not less than current one.
			 * "Lots" means "at least twice" here.
			 */
			/* 如果新的接收窗口不为0，且比原来接收窗口的剩余量大了一倍以上，
			 * 就说接收窗口显著增大了,需要立即发送ACK告知对端
			 */
			if (new_window && new_window >= 2 * rcv_window_now)
				time_to_ack = 1;
		}
	}
	if (time_to_ack)
		tcp_send_ack(sk); /* 发送ACK给对端 */
}

/* 接收prequeue */
static void tcp_prequeue_process(struct sock *sk)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);

	NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPPREQUEUED);

	/* RX process wants to run with disabled BHs, though it is not
	 * necessary */
	local_bh_disable(); /* 接收数据包前先禁用本地软中断 */
	/* 循环处理prequeue中的数据包 */
	while ((skb = __skb_dequeue(&tp->ucopy.prequeue)) != NULL)
		sk_backlog_rcv(sk, skb);
	local_bh_enable();

	/* Clear memory counter. */
	tp->ucopy.memory = 0;
}

static inline struct sk_buff *tcp_recv_skb(struct sock *sk, u32 seq, u32 *off)
{
	struct sk_buff *skb;
	u32 offset;

	skb_queue_walk(&sk->sk_receive_queue, skb) {
		offset = seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			offset--;
		if (offset < skb->len || tcp_hdr(skb)->fin) {
			*off = offset;
			return skb;
		}
	}
	return NULL;
}

/*
 * This routine provides an alternative to tcp_recvmsg() for routines
 * that would like to handle copying from skbuffs directly in 'sendfile'
 * fashion.
 * Note:
 *	- It is assumed that the socket was locked by the caller.
 *	- The routine does not block.
 *	- At present, there is no support for reading OOB data
 *	  or for 'peeking' the socket using this routine
 *	  (although both would be easy to implement).
 */
int tcp_read_sock(struct sock *sk, read_descriptor_t *desc,
		  sk_read_actor_t recv_actor)
{
	struct sk_buff *skb;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 seq = tp->copied_seq;
	u32 offset;
	int copied = 0;

	if (sk->sk_state == TCP_LISTEN)
		return -ENOTCONN;
	while ((skb = tcp_recv_skb(sk, seq, &offset)) != NULL) {
		if (offset < skb->len) {
			int used;
			size_t len;

			len = skb->len - offset;
			/* Stop reading if we hit a patch of urgent data */
			if (tp->urg_data) {
				u32 urg_offset = tp->urg_seq - seq;
				if (urg_offset < len)
					len = urg_offset;
				if (!len)
					break;
			}
			used = recv_actor(desc, skb, offset, len);
			if (used < 0) {
				if (!copied)
					copied = used;
				break;
			} else if (used <= len) {
				seq += used;
				copied += used;
				offset += used;
			}
			/*
			 * If recv_actor drops the lock (e.g. TCP splice
			 * receive) the skb pointer might be invalid when
			 * getting here: tcp_collapse might have deleted it
			 * while aggregating skbs from the socket queue.
			 */
			skb = tcp_recv_skb(sk, seq-1, &offset);
			if (!skb || (offset+1 != skb->len))
				break;
		}
		if (tcp_hdr(skb)->fin) {
			sk_eat_skb(sk, skb, 0);
			++seq;
			break;
		}
		sk_eat_skb(sk, skb, 0);
		if (!desc->count)
			break;
	}
	tp->copied_seq = seq;

	tcp_rcv_space_adjust(sk);

	/* Clean up data we have read: This will do ACK frames. */
	if (copied > 0)
		tcp_cleanup_rbuf(sk, copied);
	return copied;
}

/*
 *	This routine copies from a sock struct into the user buffer.
 *
 *	Technical note: in 2.3 we work on _locked_ socket, so that
 *	tricks with *seq access order and skb->users are not required.
 *	Probably, code can be easily improved even more.
 */

/* 
 * @len:为需要读取的总大小,即msg->msg_iov数组中iov_len之和 
 * @nonblock: 0为阻塞读,1为非阻塞
 */
int tcp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int nonblock, int flags, int *addr_len)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int copied = 0; 	/* 表示已经读取到应用层的大小 */
	u32 peek_seq;
	u32 *seq;		/* 指向tp->copied_seq */
	unsigned long used;	/* 表示skb中可被读取到应用层的数据大小 */
	int err;
	int target;		/* Read at least this many bytes */
				/* target为本次调用至少读取的长度 */
	long timeo;		/* 阻塞超时时间 */
	struct task_struct *user_recv = NULL;
	int copied_early = 0;
	struct sk_buff *skb;
	u32 urg_hole = 0;

	lock_sock(sk); /* 设置sk->sk_lock.owned, 可能等待其他进程退出 */

	TCP_CHECK_TIMER(sk);

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN) /* 监听的不能接收数据 */
		goto out;

	/* 获取读超时时间, 非阻塞为0 */
	timeo = sock_rcvtimeo(sk, nonblock);

	/* Urgent data needs to be handled specially. */
	/* 如果使用了带外数据,则特殊处理 */
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &tp->copied_seq; /* 下一个读取序列号 */

	/* 如果使用了预读MSG_PEEK(即预先读取但是数据不从协议删除)
	 * 则不能修改tp->copied_seq
	 */ 
	if (flags & MSG_PEEK) {
		peek_seq = tp->copied_seq;
		seq = &peek_seq;
	}

	/* 获取目标读取的字节数,至少需要读取target字节才能返回
	 * MSG_WAITALL标志表示需要读取recv指定的len长度才能返回
	 */
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

#ifdef CONFIG_NET_DMA
	tp->ucopy.dma_chan = NULL;
	preempt_disable();
	skb = skb_peek_tail(&sk->sk_receive_queue);
	{
		int available = 0;

		if (skb)
			/* available为receive queue可读取的字节数 */
			available = TCP_SKB_CB(skb)->seq + skb->len - (*seq);
		/*
		 * tp->ucopy.pinned_list 指向DMA需要的dma_pinned_list结构,如果为空则表示不使用DMA拷贝
		 * 使用DMA与否就由这里来控制,当以下条件满足时才使用DMA：
		 *  1. receive queue中的数据小于最小需要的
		 *  2. 应用层提供的缓存大小大于tcp_dma_copybreak,默认为4k
		 *  3. 非预读MSG_PEEK模式
		 *  4. tcp_low_latency低延迟模式关闭
		 *  5. 找到dma channel
		 */
		if ((available < target) &&
		    (len > sysctl_tcp_dma_copybreak) && !(flags & MSG_PEEK) &&
		    !sysctl_tcp_low_latency &&
		    dma_find_channel(DMA_MEMCPY)) {
			preempt_enable_no_resched();
			/* 分配一个dma_pinned_list并根据iovec数组初始化 */
			tp->ucopy.pinned_list =
					dma_pin_iovec_pages(msg->msg_iov, len);
		} else {
			preempt_enable_no_resched();
		}
	}
#endif

	do {
		u32 offset; /* skb起始seq距离copied_seq的长度,
			     * 即从skb偏移offset的位置开始读取数据
			     */

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (tp->urg_data && tp->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		/* Next get a buffer. */

		/* 找到包含copied_seq的待接收的skb
		 * 找到后则跳转到found_ok_skb处理
		 */
		skb_queue_walk(&sk->sk_receive_queue, skb) {
			/* Now that we have two receive queues this
			 * shouldn't happen.
			 */
			/* 如果要skb的seq在copied_seq之后,则出现了BUG */
			if (WARN(before(*seq, TCP_SKB_CB(skb)->seq),
			     KERN_INFO "recvmsg bug: copied %X "
				       "seq %X rcvnxt %X fl %X\n", *seq,
				       TCP_SKB_CB(skb)->seq, tp->rcv_nxt,
				       flags))
				break;
			/* offset为skb的序列号与要下一个要接收序列号的距离 */
			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (tcp_hdr(skb)->syn) /* 去掉SYN的序列号 */
				offset--;
			/* 如果offset小于skb->len, 说明skb包含有将要读取的数据
			 * 即找到目标skb
			 */
			if (offset < skb->len)
				goto found_ok_skb;
			/* 如果是FIN包则跳转处理 */
			if (tcp_hdr(skb)->fin)
				goto found_fin_ok;
			WARN(!(flags & MSG_PEEK), KERN_INFO "recvmsg bug 2: "
					"copied %X seq %X rcvnxt %X fl %X\n",
					*seq, TCP_SKB_CB(skb)->seq,
					tp->rcv_nxt, flags);
		}

		/* Well, if we have backlog, try to process it now yet. */

		/* 
		 * 到这里说明receive queue里没有可接收的数据了
		 * 以下可能要处理prequeue和backlog队列了
		 */

		/* 如果已读取的不小于最小需要读取的并且backlog队列为空,就可以退出了 
		 * 因为如果backlog有数据包的话虽然已经可以返回但还是可以继续读到更多数据的
		 */
		if (copied >= target && !sk->sk_backlog.tail)
			break;

		/* 这个if-else用来判断一些不需要继续等待接收的乱七八糟的情况, 以便直接breck出去 */
		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		tcp_cleanup_rbuf(sk, copied); /* 检查现在是否需要发送ACK */

		/* 不开启tcp_low_latency的情况下
		 *     (低延迟模式,默认不开启,开启后不使用prequeue,
		 * 	这样TCP协议处理的延时较低,比如ACK回复较为及时,
		 * 	因为tcp_v4_rcv收到数据时不进入prequeue然后在唤醒应用层后才处理)
		 *
		 * 并且sock未设置等待处理的进程或已经设置并且是本进程,
		 * 则进入处理prequeue
		 */
		if (!sysctl_tcp_low_latency && tp->ucopy.task == user_recv) {
			/* Install new reader */
			/* 设置正在读的进程为current, 以便prequeue处理接收 */
			if (!user_recv && !(flags & (MSG_TRUNC | MSG_PEEK))) {
				user_recv = current;
				tp->ucopy.task = user_recv;
				tp->ucopy.iov = msg->msg_iov;
			}

			tp->ucopy.len = len; /* 设置还需要读取的大小 */

			/* 这个警告说明这里receive queue必须为空 */
			WARN_ON(tp->copied_seq != tp->rcv_nxt &&
				!(flags & (MSG_PEEK | MSG_TRUNC)));

			/* Ugly... If prequeue is not empty, we have to
			 * process it before releasing socket, otherwise
			 * order will be broken at second iteration.
			 * More elegant solution is required!!!
			 *
			 * Look: we have the following (pseudo)queues:
			 *
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 *
			 * Each queue can be processed only if the next ones
			 * are empty. At this point we have empty receive_queue.
			 * But prequeue _can_ be not empty after 2nd iteration,
			 * when we jumped to start of loop because backlog
			 * processing added something to receive_queue.
			 * We cannot release_sock(), because backlog contains
			 * packets arrived _after_ prequeued ones.
			 *
			 * Shortly, algorithm is clear --- to process all
			 * the queues in order. We could make it more directly,
			 * requeueing packets from backlog to prequeue, if
			 * is not empty. It is more elegant, but eats cycles,
			 * unfortunately.
			 */

			/* 以上这段注释解释的很清楚了, 大意是：
			 * 我们有4个队列(确切的说是3个队列和链路上的数据):
			 * 1. packets in flight
			 * 2. backlog
			 * 3. prequeue
			 * 4. receive_queue
			 * 为了确保不会因为这几个队列导致数据包的人为乱序,
			 * 需要确保处理严格按照数据包到达的顺序.
			 * 所以以上4个队列的处理需要满足在其下一个队列的数据包未处理完前不能处理.
			 *
			 * 而现在这个地方是4.receive_queue为空,
			 * 所以需要先处理3.prequeue,因为以下可能调用release_sock()来处理2.backlog
			 */

			/* 如果prequeue非空,则先处理prequeue */
			if (!skb_queue_empty(&tp->ucopy.prequeue))
				goto do_prequeue;

			/* __ Set realtime policy in scheduler __ */
		}

		/* 
		 * 到达这里说明recrive queue和prequeue都处理完为空了 
		 * 可以处理backlog了
		 */

		/* 已经拷贝的满足最小需要读取的,
		 * 那么不需要睡眠了, 仅仅调用release_sock()来处理backlog
		 */
		if (copied >= target) {
			/* Do not sleep, just process backlog. */
			release_sock(sk); /* 目的是为了处理backlog */
			lock_sock(sk);	/* 马上又hold住sock */
		} else
			/* 这里可能就需要睡眠等待了, timeo为等待超时时间
			 * sk_wait_data里会接收backlog,如果有数据则不会睡眠直接返回
			 * 否则等待过程中prequeue收到新数据则唤醒返回
			 */
			sk_wait_data(sk, &timeo);

#ifdef CONFIG_NET_DMA
		tp->ucopy.wakeup = 0;
#endif

		/* 如果sock有设置过进程读等待关联 */
		if (user_recv) {
			int chunk;

			/* __ Restore normal policy in scheduler __ */

			/* 因为上面可能在处理backlog时进程接收过数据,
			 * 所以这里需要调整下剩余需要读的和已经读的大小 
			 */
			if ((chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMBACKLOG, chunk);
				len -= chunk;
				copied += chunk;
			}

			/* 如果receive queue中已经没有数据可读且prequeue有数据包，
			 * 那么处理prequeue队列接收数据包
			 * 这里需要再次判断receive queue是否为空是因为前面处理了backlog, 
			 * 数据包可能从backlog转移到了receive queue,
			 * 那么就要优先处理receive queue
			 */
			if (tp->rcv_nxt == tp->copied_seq &&
			    !skb_queue_empty(&tp->ucopy.prequeue)) {
do_prequeue:
				tcp_prequeue_process(sk); /* 接收prequeue的数据包 */

				/* 因为上面处理prequeue时可能以下通过函数调用关系:
				 * 	tcp_prequeue_process 
				 * 	  => tcp_v4_do_rcv 
				 * 	    => tcp_rcv_established 
				 * 	      => tcp_data_queue 
				 * 	        => skb_copy_datagram_iovec
				 * 返回这里时prequeue已经处理过了, 
				 * tp->ucopu.len在处理prequeue之前等于len, 而现在已经更新成还需要接收的大小,
				 * 所以,len - tp->ucopy.len 即表示在prequeue中处理接收的大小
				 */
				if ((chunk = len - tp->ucopy.len) != 0) {
					NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
					/* 调整prequeue中处理接收的长度 */
					len -= chunk;
					copied += chunk;
				}
			}
		}

		/* 检查预读的情况下序列号出错 */
		if ((flags & MSG_PEEK) &&
		    (peek_seq - copied - urg_hole != tp->copied_seq)) {
			if (net_ratelimit())
				printk(KERN_DEBUG "TCP(%s:%d): Application bug, race in MSG_PEEK.\n",
				       current->comm, task_pid_nr(current));
			peek_seq = tp->copied_seq;
		}
		continue; /* 这里处理了prequeue或者backlog, 从receive queue开始再继续尝试接收数据 */

	found_ok_skb:
		/* 这里找到了将要接收的skb */

		/* Ok so how much can we use? */
		used = skb->len - offset; /* used为该skb中能被接收的有效数据长度 */
		if (len < used) /* 如果大于应用层需要的则减少 */
			used = len;

		/* Do we have urgent data here? */
		if (tp->urg_data) {
			u32 urg_offset = tp->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						urg_hole++;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}

		/* 这里处理拷贝数据到应用层,
		 * 如果含有MSG_TRUNC标志则不需要进行拷贝操作
		 * (MSG_TRUNC表示应用层不需要具体数据,相当于这部分数据从协议栈直接清除)
		 */
		if (!(flags & MSG_TRUNC)) {
#ifdef CONFIG_NET_DMA
			/* 如果使用DMA则获取dma channel */
			if (!tp->ucopy.dma_chan && tp->ucopy.pinned_list)
				tp->ucopy.dma_chan = dma_find_channel(DMA_MEMCPY);

			/* 获取dma channel之后, 使用DMA拷贝数据,
			 * dma_skb_copy_datagram_iovec()将skb需要拷贝的数据映射到iovec中,
			 * 但是拷贝是异步的,返回后仅是通知DMA操作,并不意味着拷贝完成
			 * 等到之后调用dma_async_memcpy_complete()来等待DMA拷贝完成
			 */
			if (tp->ucopy.dma_chan) {
				tp->ucopy.dma_cookie = dma_skb_copy_datagram_iovec(
					tp->ucopy.dma_chan, skb, offset,
					msg->msg_iov, used,
					tp->ucopy.pinned_list);

				if (tp->ucopy.dma_cookie < 0) {

					printk(KERN_ALERT "dma_cookie < 0\n");

					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
				/* 如果整个skb的数据都被读取了,设置copied_early为1
				 * 原因是如果是正常同步读取的话当整个skb的数据都被读取之后以下sk_eat_skb()就可以将skb释放了
				 * 但是这里因为DMA是异步读取,所以skb还不能释放,
				 * 将copied_early置1以便sk_eat_skb()中先将skb加入sk->sk_async_wait_queue队列,
				 * 然后等DMA拷贝完成再从队列中删除
				 */
				if ((offset + used) == skb->len)
					copied_early = 1;

			} else
#endif
			{
				/* 从skb中偏移offset的位置开始拷贝used字节到应用层 */
				err = skb_copy_datagram_iovec(skb, offset,
						msg->msg_iov, used);
				if (err) { /* 拷贝出错 */
					/* Exception. Bailout! */
					if (!copied)
						copied = -EFAULT;
					break;
				}
			}
		}

		*seq += used;	/* 读取后增加copied_seq, 预读的情况不修改copied_seq(seq指向临时变量) */
		copied += used;	/* 增加已经读取的长度 */
		len -= used;	/* 减小还需要读取的长度 */

		tcp_rcv_space_adjust(sk); /* 调整接收缓存 */

skip_copy:
		if (tp->urg_data && after(tp->copied_seq, tp->urg_seq)) {
			tp->urg_data = 0;
			tcp_fast_path_check(sk);
		}
		/* 满足条件说明skb还存在未读取的数据 */
		if (used + offset < skb->len)
			continue;

		/* 到这里说明该skb的数据都被读取了 */

		/* 如果是FIN包则处理 */
		if (tcp_hdr(skb)->fin)
			goto found_fin_ok;
		/* 如果不是预读，则将skb从接收队列删除并释放skb */
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		continue; /* 继续处理 */

	found_fin_ok:
		/* 这里处理FIN, 如果非预读则skb可以删除并释放了,
		 * 同时break退出
		 */
		/* Process the FIN. */
		++*seq;
		if (!(flags & MSG_PEEK)) {
			sk_eat_skb(sk, skb, copied_early);
			copied_early = 0;
		}
		break;
	} while (len > 0); /* len为应用层缓存还能接收的大小, 还有空间则继续处理 */

	/* 到达这里说明数据已经读取完,
	 * 如果上面sock有设置过进程读等待关联, 那么这里需要去掉关联了
	 * 去掉关联前还是需要先处理prequeue队列
	 */
	if (user_recv) {
		/* 先处理下prequeue队列 */
		if (!skb_queue_empty(&tp->ucopy.prequeue)) {
			int chunk;

			tp->ucopy.len = copied > 0 ? len : 0;

			tcp_prequeue_process(sk);

			if (copied > 0 && (chunk = len - tp->ucopy.len) != 0) {
				NET_ADD_STATS_USER(sock_net(sk), LINUX_MIB_TCPDIRECTCOPYFROMPREQUEUE, chunk);
				len -= chunk;
				copied += chunk;
			}
		}

		/* 去掉sock和进程的读关联 */
		tp->ucopy.task = NULL;
		tp->ucopy.len = 0;
	}

#ifdef CONFIG_NET_DMA
	if (tp->ucopy.dma_chan) {
		dma_cookie_t done, used;

		dma_async_memcpy_issue_pending(tp->ucopy.dma_chan);

		/* 循环等待DMA拷贝完成 */
		while (dma_async_memcpy_complete(tp->ucopy.dma_chan,
						 tp->ucopy.dma_cookie, &done,
						 &used) == DMA_IN_PROGRESS) {
			/* do partial cleanup of sk_async_wait_queue */
			/* 先清除已完成部分的skb */
			while ((skb = skb_peek(&sk->sk_async_wait_queue)) &&
			       (dma_async_is_complete(skb->dma_cookie, done,
						      used) == DMA_SUCCESS)) {
				__skb_dequeue(&sk->sk_async_wait_queue);
				kfree_skb(skb);
			}
		}

		/* Safe to free early-copied skbs now */
		/* 到这里DMA拷贝完成,清空sk_async_wait_queue队列 */
		__skb_queue_purge(&sk->sk_async_wait_queue);
		tp->ucopy.dma_chan = NULL; /* dma channel清零 */
	}
	/* 释放掉之前申请的dma_pinned_list */
	if (tp->ucopy.pinned_list) {
		dma_unpin_iovec_pages(tp->ucopy.pinned_list);
		tp->ucopy.pinned_list = NULL;
	}
#endif

	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */

	/* Clean up data we have read: This will do ACK frames. */
	tcp_cleanup_rbuf(sk, copied); /* 检查现在是否需要发送ACK */

	TCP_CHECK_TIMER(sk);
	release_sock(sk); /* 退出sock的持有,同时会处理接收backlog队列并唤醒等待sock的进程 */
	return copied; /* 返回读取的大小 */

out:
	TCP_CHECK_TIMER(sk);
	release_sock(sk);
	return err;

recv_urg:
	err = tcp_recv_urg(sk, msg, len, flags);
	goto out;
}

void tcp_set_state(struct sock *sk, int state)
{
	int oldstate = sk->sk_state;

	switch (state) {
	case TCP_ESTABLISHED:
		if (oldstate != TCP_ESTABLISHED)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
		break;

	case TCP_CLOSE:
		if (oldstate == TCP_CLOSE_WAIT || oldstate == TCP_ESTABLISHED)
			TCP_INC_STATS(sock_net(sk), TCP_MIB_ESTABRESETS);

		sk->sk_prot->unhash(sk);  /* 调用inet_unhash() */
		if (inet_csk(sk)->icsk_bind_hash &&
		    !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			inet_put_port(sk);
		/* fall through */
	default:
		if (oldstate == TCP_ESTABLISHED)
			TCP_DEC_STATS(sock_net(sk), TCP_MIB_CURRESTAB);
	}

	/* Change state AFTER socket is unhashed to avoid closed
	 * socket sitting in hash tables.
	 */
	sk->sk_state = state;

#ifdef STATE_TRACE
	SOCK_DEBUG(sk, "TCP sk=%p, State %s -> %s\n", sk, statename[oldstate], statename[state]);
#endif
}
EXPORT_SYMBOL_GPL(tcp_set_state);

/*
 *	State processing on a close. This implements the state shift for
 *	sending our FIN frame. Note that we only send a FIN for some
 *	states. A shutdown() may have already sent the FIN, or we may be
 *	closed.
 */

/* 这个数组表示各个状态下应用层close()后要切换的下一个状态
 * 注释里是原状态，值是新的状态
 * TCP_ACTION_FIN表示切换状态需要发送FIN包, 
 * 因为可能之前应用层SHUTDOWN时已经发送过FIN，
 * 所以这里并不是所有状态都需要发送FIN
 */
static const unsigned char new_state[16] = {
  /* current state:        new state:      action:	*/
  /* (Invalid)		*/ TCP_CLOSE,
  /* TCP_ESTABLISHED	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_SYN_SENT	*/ TCP_CLOSE,
  /* TCP_SYN_RECV	*/ TCP_FIN_WAIT1 | TCP_ACTION_FIN,
  /* TCP_FIN_WAIT1	*/ TCP_FIN_WAIT1,
  /* TCP_FIN_WAIT2	*/ TCP_FIN_WAIT2,
  /* TCP_TIME_WAIT	*/ TCP_CLOSE,
  /* TCP_CLOSE		*/ TCP_CLOSE,
  /* TCP_CLOSE_WAIT	*/ TCP_LAST_ACK  | TCP_ACTION_FIN,
  /* TCP_LAST_ACK	*/ TCP_LAST_ACK,
  /* TCP_LISTEN		*/ TCP_CLOSE,
  /* TCP_CLOSING	*/ TCP_CLOSING,
};

/* 处理应用层close()时的状态切换
 * 如果需要发送FIN则返回1
 */
static int tcp_close_state(struct sock *sk)
{
	int next = (int)new_state[sk->sk_state]; /* 下一个状态 */
	int ns = next & TCP_STATE_MASK;

	tcp_set_state(sk, ns); /* 设置新的状态 */

	return next & TCP_ACTION_FIN; /* 如果需要发送FIN则返回1 */
}

/*
 *	Shutdown the sending side of a connection. Much like close except
 *	that we don't receive shut down or sock_set_flag(sk, SOCK_DEAD).
 */

void tcp_shutdown(struct sock *sk, int how)
{
	/*	We need to grab some memory, and put together a FIN,
	 *	and then put it into the queue to be sent.
	 *		Tim MacKenzie(tym@dibbler.cs.monash.edu.au) 4 Dec '92.
	 */
	if (!(how & SEND_SHUTDOWN))
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT)) {
		/* Clear out any half completed packets.  FIN if needed. */
		if (tcp_close_state(sk))
			tcp_send_fin(sk);
	}
}

void tcp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	lock_sock(sk);
	sk->sk_shutdown = SHUTDOWN_MASK;

	/* 监听的单独处理 */
	if (sk->sk_state == TCP_LISTEN) {
		tcp_set_state(sk, TCP_CLOSE);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	/* 释放接收队列上的skb, 因为应用层已经关闭不再接收数据 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len; /* 统计未被应用层接收的数据长度 */
		__kfree_skb(skb); /* 释放skb */
	}

	sk_mem_reclaim(sk); /* 释放预分配内存 */

	/* As outlined in RFC 2525, section 2.17, we send a RST here because
	 * data was lost. To witness the awful effects of the old behavior of
	 * always doing a FIN, run an older 2.1.x kernel or 2.0.x, start a bulk
	 * GET in an FTP client, suspend the process, wait for the client to
	 * advertise a zero window, then kill -9 the FTP client, wheee...
	 * Note: timeout is always zero in such a case.
	 */
	if (data_was_unread) {
		/* 如果有应用层未接受的数据，那么回复RST */
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE); /* 设置为CLOSE状态 */
		tcp_send_active_reset(sk, sk->sk_allocation); /* 发送RESET */
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* 如果设置了SO_LINGER并且timeout设置为0,
		 * 那么直接tcp_disconnect()清理各种队列
		 * 并且tcp_disconnect()会发送RST
		 */
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0); /* 调用tcp_disconnect() */
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONDATA);
	} else if (tcp_close_state(sk)) { /* 处理状态切换，返回1表示需要发送FIN包 */
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		/* RED-PEN. Formally speaking, we have broken TCP state
		 * machine. State transitions:
		 *
		 * TCP_ESTABLISHED -> TCP_FIN_WAIT1
		 * TCP_SYN_RECV	-> TCP_FIN_WAIT1 (forget it, it's impossible)
		 * TCP_CLOSE_WAIT -> TCP_LAST_ACK
		 *
		 * are legal only when FIN has been sent (i.e. in window),
		 * rather than queued out of window. Purists blame.
		 *
		 * F.e. "RFC state" is ESTABLISHED,
		 * if Linux state is FIN-WAIT-1, but FIN is still not sent.
		 *
		 * The visible declinations are that sometimes
		 * we enter time-wait state, when it is not required really
		 * (harmless), do not send active resets, when they are
		 * required by specs (TCP_ESTABLISHED, TCP_CLOSE_WAIT, when
		 * they look as CLOSING or LAST_ACK for Linux)
		 * Probably, I missed some more holelets.
		 * 						--ANK
		 */
		tcp_send_fin(sk); /* 发送FIN包/增加FIN标志 */
	}

	/* 如果设置了SO_LINGER则阻塞等待对端确认所有数据(包括FIN)
	 * 或者timeout时间超时才返回
	 */
	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk); /* 脱离sock和socket的关系 */

	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);


	/* Now socket is owned by kernel and we acquire BH lock
	   to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	WARN_ON(sock_owned_by_user(sk));

	percpu_counter_inc(sk->sk_prot->orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		goto out;

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	/* 如果此时为FIN_WAIT2状态，可以直接进入TIME_WAIT(真实状态还是FIN_WAIT2)，后面接收FIN包由TIME_WAIT代理
	 * 对应先处于FIN_WAIT2状态然后应用层再close()的情况
	 * 比如：
	 * 	之前应用层已经SHUTDOWN发送了FIN并且接收ACK进入了FIN_WAIT2状态，
	 * 	然后现在应用层又close()了
	 */
	if (sk->sk_state == TCP_FIN_WAIT2) {
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->linger2 < 0) { /* 如果为负数则直接关闭sock并发送RST */
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPABORTONLINGER);
		} else {
			const int tmo = tcp_fin_time(sk); /* 获取FIN_WAIT2的超时时间 */

			/* 如果FIN_WAIT2超时时间大于TIMEWAIT的超时时间，
			 * 那么先触发差值的keepalive，keepalive后再触发等待差值的FIN_WAIT2,
			 * 接下来如果进入TIME_WAIT还需要等待TCP_TIMEWAIT_LEN的TIME_WAIT超时时间
			 */
			if (tmo > TCP_TIMEWAIT_LEN) {
				inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
			} else { /* 否则直接等待tmo的FIN_WAIT2超时 */
				tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
				goto out;
			}
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		int orphan_count = percpu_counter_read_positive(
						sk->sk_prot->orphan_count);

		sk_mem_reclaim(sk);
		if (tcp_too_many_orphans(sk, orphan_count)) {
			if (net_ratelimit())
				printk(KERN_INFO "TCP: too many of orphaned "
				       "sockets\n");
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					LINUX_MIB_TCPABORTONMEMORY);
		}
	}

	if (sk->sk_state == TCP_CLOSE)
		inet_csk_destroy_sock(sk);
	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/* These states need RST on ABORT according to RFC793 */
/* 断开连接时需要给对端发送RST的状态,
 * 这些状态的共同点是还未正常四次握手
 */
static inline int tcp_need_reset(int state)
{
	return (1 << state) &
	       (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT | TCPF_FIN_WAIT1 |
		TCPF_FIN_WAIT2 | TCPF_SYN_RECV);
}

int tcp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int err = 0;
	int old_state = sk->sk_state;

	if (old_state != TCP_CLOSE)
		tcp_set_state(sk, TCP_CLOSE);

	/* ABORT function of RFC793 */
	if (old_state == TCP_LISTEN) {
		inet_csk_listen_stop(sk);
	} else if (tcp_need_reset(old_state) ||
		   (tp->snd_nxt != tp->write_seq &&
		    (1 << old_state) & (TCPF_CLOSING | TCPF_LAST_ACK))) {
		/* 以下两种情况需要发送reset:
		 * 1. 处于ESTABLISTED/CLOSE_WAIT/FIN_WAIT1/FIN_WAIT2/SYN_RECV
		 * 2. CLOSING/LAST_ACK状态下还有没发送完的数据 
		 */
		/* The last check adjusts for discrepancy of Linux wrt. RFC
		 * states
		 */
		tcp_send_active_reset(sk, gfp_any()); /* 发送reset */
		sk->sk_err = ECONNRESET;
	} else if (old_state == TCP_SYN_SENT)
		sk->sk_err = ECONNRESET;

	tcp_clear_xmit_timers(sk); /*清除各种定时器 */
	__skb_queue_purge(&sk->sk_receive_queue); /* 清理接收队列 */
	tcp_write_queue_purge(sk); /* 清理发送队列 */
	__skb_queue_purge(&tp->out_of_order_queue); /* 清理乱序队列 */
#ifdef CONFIG_NET_DMA
	__skb_queue_purge(&sk->sk_async_wait_queue);
#endif

	inet->dport = 0;

	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	sk->sk_shutdown = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->srtt = 0;
	if ((tp->write_seq += tp->max_window + 2) == 0)
		tp->write_seq = 1;
	icsk->icsk_backoff = 0;
	tp->snd_cwnd = 2;
	icsk->icsk_probes_out = 0;
	tp->packets_out = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	tp->snd_cwnd_cnt = 0;
	tp->bytes_acked = 0;
	tcp_set_ca_state(sk, TCP_CA_Open);
	tcp_clear_retrans(tp);
	inet_csk_delack_init(sk);
	tcp_init_send_head(sk);
	memset(&tp->rx_opt, 0, sizeof(tp->rx_opt));
	__sk_dst_reset(sk);

	WARN_ON(inet->num && !icsk->icsk_bind_hash);

	sk->sk_error_report(sk);
	return err;
}

/*
 *	Socket option code for TCP.
 */
static int do_tcp_setsockopt(struct sock *sk, int level,
		int optname, char __user *optval, unsigned int optlen)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int val;
	int err = 0;

	/* This is a string value all the others are int's */
	if (optname == TCP_CONGESTION) {
		char name[TCP_CA_NAME_MAX];

		if (optlen < 1)
			return -EINVAL;

		val = strncpy_from_user(name, optval,
					min_t(long, TCP_CA_NAME_MAX-1, optlen));
		if (val < 0)
			return -EFAULT;
		name[val] = 0;

		lock_sock(sk);
		err = tcp_set_congestion_control(sk, name);
		release_sock(sk);
		return err;
	}

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_MAXSEG:
		/* Values greater than interface MTU won't take effect. However
		 * at the point when this call is done we typically don't yet
		 * know which interface is going to be used */
		if (val < TCP_MIN_MSS || val > MAX_TCP_WINDOW) {
			err = -EINVAL;
			break;
		}
		tp->rx_opt.user_mss = val;
		break;

	case TCP_NODELAY:
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			tp->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk);
		} else {
			tp->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;

	case TCP_THIN_LINEAR_TIMEOUTS:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_lto = val;
		break;

	case TCP_THIN_DUPACK:
		if (val < 0 || val > 1)
			err = -EINVAL;
		else
			tp->thin_dupack = val;
		break;

	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			tp->nonagle |= TCP_NAGLE_CORK;
		} else {
			tp->nonagle &= ~TCP_NAGLE_CORK;
			if (tp->nonagle&TCP_NAGLE_OFF)
				tp->nonagle |= TCP_NAGLE_PUSH;
			tcp_push_pending_frames(sk);
		}
		break;

	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			tp->keepalive_time = val * HZ; /* 设置新的空闲时间 */
			/* 如果有使用SO_KEEPALIVE选项，并且连接处于非监听非结束的状态。 
			 * 这个时候保活定时器已经在计时了，这里设置新的超时时间
			 */
			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) &
			      (TCPF_CLOSE | TCPF_LISTEN))) {
				u32 elapsed = keepalive_time_elapsed(tp); /* 连接已经经历的空闲时间 */
				if (tp->keepalive_time > elapsed) /* 时间还未到 */
					elapsed = tp->keepalive_time - elapsed;
				else /* 时间已经到了, 马上触发keepalive定时器 */
					elapsed = 0;
				inet_csk_reset_keepalive_timer(sk, elapsed);
			}
		}
		break;
	case TCP_KEEPINTVL:
		if (val < 1 || val > MAX_TCP_KEEPINTVL)
			err = -EINVAL;
		else
			tp->keepalive_intvl = val * HZ; /* 设置新的探测报文间隔 */
		break;
	case TCP_KEEPCNT:
		if (val < 1 || val > MAX_TCP_KEEPCNT)
			err = -EINVAL;
		else
			tp->keepalive_probes = val; /* 设置新的探测次数 */
		break;
	case TCP_SYNCNT:
		if (val < 1 || val > MAX_TCP_SYNCNT)
			err = -EINVAL;
		else
			icsk->icsk_syn_retries = val;
		break;

	case TCP_LINGER2: /* 设置在应用层close()后FIN_WAIT2状态的超时时间 */
		if (val < 0) 
			/* 负数表示应用层close()后如果处于FIN_WAIT2状态那么直接关闭连接并向对端发送reset */
			tp->linger2 = -1;
		else if (val > sysctl_tcp_fin_timeout / HZ)
			/* 如果val大于tcp_fin_timeout那么设置无效，等同于0, 即超时时间为tcp_fin_timeout */
			tp->linger2 = 0;
		else
			/* 应用层close()后FIN_WAIT2状态会等待val秒的时间, 超时后内核直接关闭连接 */
			tp->linger2 = val * HZ;
		break;

	case TCP_DEFER_ACCEPT:
		/* Translate value in seconds to number of retransmits */
		icsk->icsk_accept_queue.rskq_defer_accept =
			secs_to_retrans(val, TCP_TIMEOUT_INIT / HZ,
					TCP_RTO_MAX / HZ);
		break;

	case TCP_WINDOW_CLAMP:
		if (!val) {
			if (sk->sk_state != TCP_CLOSE) {
				err = -EINVAL;
				break;
			}
			tp->window_clamp = 0;
		} else
			tp->window_clamp = val < SOCK_MIN_RCVBUF / 2 ?
						SOCK_MIN_RCVBUF / 2 : val;
		break;

	case TCP_QUICKACK:
		if (!val) {
			icsk->icsk_ack.pingpong = 1; /* 禁用快速确认模式 */
		} else {
			icsk->icsk_ack.pingpong = 0; /* 启用快速确认模式 */
			/* 如果当前有ACK需要发送，就立即发送 */
			if ((1 << sk->sk_state) &
			    (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT) &&
			    inet_csk_ack_scheduled(sk)) {
				icsk->icsk_ack.pending |= ICSK_ACK_PUSHED; /* 允许在快速模式中立即发送 */
				
				/* 通常当接收队列中有数据复制到用户空间时，会调用此函数来判断是否需要立即发送ACK。 
				 * 这里的用法比较特殊，由于设置了ICSK_ACK_PUSHED标志，且处于快速确认模式中， 
				 * 必然会立即发送ACK
				 */
				tcp_cleanup_rbuf(sk, 1);
				/* 如果选项的值为偶数，那么立即退出快速确认模式 */
				if (!(val & 1))
					icsk->icsk_ack.pingpong = 1;
			}
		}
		break;

#ifdef CONFIG_TCP_MD5SIG
	case TCP_MD5SIG:
		/* Read the IP->Key mappings from userspace */
		err = tp->af_specific->md5_parse(sk, optval, optlen);
		break;
#endif

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

int tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   unsigned int optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)
		return icsk->icsk_af_ops->setsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_tcp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_setsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_setsockopt(sk, level, optname, optval, optlen);
}

EXPORT_SYMBOL(compat_tcp_setsockopt);
#endif

/* Return information about state of tcp endpoint in API format. */
void tcp_get_info(struct sock *sk, struct tcp_info *info)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 now = tcp_time_stamp;

	memset(info, 0, sizeof(*info));

	info->tcpi_state = sk->sk_state;
	info->tcpi_ca_state = icsk->icsk_ca_state;
	info->tcpi_retransmits = icsk->icsk_retransmits;
	info->tcpi_probes = icsk->icsk_probes_out;
	info->tcpi_backoff = icsk->icsk_backoff;

	if (tp->rx_opt.tstamp_ok)
		info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (tcp_is_sack(tp))
		info->tcpi_options |= TCPI_OPT_SACK;
	if (tp->rx_opt.wscale_ok) {
		info->tcpi_options |= TCPI_OPT_WSCALE;
		info->tcpi_snd_wscale = tp->rx_opt.snd_wscale;
		info->tcpi_rcv_wscale = tp->rx_opt.rcv_wscale;
	}

	if (tp->ecn_flags&TCP_ECN_OK)
		info->tcpi_options |= TCPI_OPT_ECN;

	info->tcpi_rto = jiffies_to_usecs(icsk->icsk_rto);
	info->tcpi_ato = jiffies_to_usecs(icsk->icsk_ack.ato);
	info->tcpi_snd_mss = tp->mss_cache;
	info->tcpi_rcv_mss = icsk->icsk_ack.rcv_mss;

	if (sk->sk_state == TCP_LISTEN) {
		info->tcpi_unacked = sk->sk_ack_backlog;
		info->tcpi_sacked = sk->sk_max_ack_backlog;
	} else {
		info->tcpi_unacked = tp->packets_out;
		info->tcpi_sacked = tp->sacked_out;
	}
	info->tcpi_lost = tp->lost_out;
	info->tcpi_retrans = tp->retrans_out;
	info->tcpi_fackets = tp->fackets_out;

	info->tcpi_last_data_sent = jiffies_to_msecs(now - tp->lsndtime);
	info->tcpi_last_data_recv = jiffies_to_msecs(now - icsk->icsk_ack.lrcvtime);
	info->tcpi_last_ack_recv = jiffies_to_msecs(now - tp->rcv_tstamp);

	info->tcpi_pmtu = icsk->icsk_pmtu_cookie;
	info->tcpi_rcv_ssthresh = tp->rcv_ssthresh;
	info->tcpi_rtt = jiffies_to_usecs(tp->srtt)>>3;
	info->tcpi_rttvar = jiffies_to_usecs(tp->mdev)>>2;
	info->tcpi_snd_ssthresh = tp->snd_ssthresh;
	info->tcpi_snd_cwnd = tp->snd_cwnd;
	info->tcpi_advmss = tp->advmss;
	info->tcpi_reordering = tp->reordering;

	info->tcpi_rcv_rtt = jiffies_to_usecs(tp->rcv_rtt_est.rtt)>>3;
	info->tcpi_rcv_space = tp->rcvq_space.space;

	info->tcpi_total_retrans = tp->total_retrans;
}

EXPORT_SYMBOL_GPL(tcp_get_info);

static int do_tcp_getsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_MAXSEG:
		val = tp->mss_cache;
		if (!val && ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
			val = tp->rx_opt.user_mss;
		break;
	case TCP_NODELAY:
		val = !!(tp->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(tp->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = keepalive_time_when(tp) / HZ;
		break;
	case TCP_KEEPINTVL:
		val = keepalive_intvl_when(tp) / HZ;
		break;
	case TCP_KEEPCNT:
		val = keepalive_probes(tp);
		break;
	case TCP_SYNCNT:
		val = icsk->icsk_syn_retries ? : sysctl_tcp_syn_retries;
		break;
	case TCP_LINGER2:
		val = tp->linger2;
		if (val >= 0)
			val = (val ? : sysctl_tcp_fin_timeout) / HZ;
		break;
	case TCP_DEFER_ACCEPT:
		val = retrans_to_secs(icsk->icsk_accept_queue.rskq_defer_accept,
				      TCP_TIMEOUT_INIT / HZ, TCP_RTO_MAX / HZ);
		break;
	case TCP_WINDOW_CLAMP:
		val = tp->window_clamp;
		break;
	case TCP_INFO: {
		struct tcp_info info;

		if (get_user(len, optlen))
			return -EFAULT;

		tcp_get_info(sk, &info);

		len = min_t(unsigned int, len, sizeof(info));
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &info, len))
			return -EFAULT;
		return 0;
	}
	case TCP_QUICKACK:
		val = !icsk->icsk_ack.pingpong;
		break;

	case TCP_CONGESTION:
		if (get_user(len, optlen))
			return -EFAULT;
		len = min_t(unsigned int, len, TCP_CA_NAME_MAX);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, icsk->icsk_ca_ops->name, len))
			return -EFAULT;
		return 0;
	case TCP_THIN_LINEAR_TIMEOUTS:
		val = tp->thin_lto;
		break;
	case TCP_THIN_DUPACK:
		val = tp->thin_dupack;
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

int tcp_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		   int __user *optlen)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (level != SOL_TCP)
		return icsk->icsk_af_ops->getsockopt(sk, level, optname,
						     optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_tcp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_TCP)
		return inet_csk_compat_getsockopt(sk, level, optname,
						  optval, optlen);
	return do_tcp_getsockopt(sk, level, optname, optval, optlen);
}

EXPORT_SYMBOL(compat_tcp_getsockopt);
#endif

struct sk_buff *tcp_tso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct tcphdr *th;
	unsigned thlen;
	unsigned int seq;
	__be32 delta;
	unsigned int oldlen;
	unsigned int mss;

	if (!pskb_may_pull(skb, sizeof(*th)))
		goto out;

	th = tcp_hdr(skb);
	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	if (!pskb_may_pull(skb, thlen))
		goto out;

	oldlen = (u16)~skb->len;
	__skb_pull(skb, thlen);

	mss = skb_shinfo(skb)->gso_size;
	if (unlikely(skb->len <= mss))
		goto out;

	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		/* Packet is from an untrusted source, reset gso_segs. */
		int type = skb_shinfo(skb)->gso_type;

		if (unlikely(type &
			     ~(SKB_GSO_TCPV4 |
			       SKB_GSO_DODGY |
			       SKB_GSO_TCP_ECN |
			       SKB_GSO_TCPV6 |
			       0) ||
			     !(type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))))
			goto out;

		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, mss);

		segs = NULL;
		goto out;
	}

	segs = skb_segment(skb, features);
	if (IS_ERR(segs))
		goto out;

	delta = htonl(oldlen + (thlen + mss));

	skb = segs;
	th = tcp_hdr(skb);
	seq = ntohl(th->seq);

	do {
		th->fin = th->psh = 0;

		th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				       (__force u32)delta));
		if (skb->ip_summed != CHECKSUM_PARTIAL)
			th->check =
			     csum_fold(csum_partial(skb_transport_header(skb),
						    thlen, skb->csum));

		seq += mss;
		skb = skb->next;
		th = tcp_hdr(skb);

		th->seq = htonl(seq);
		th->cwr = 0;
	} while (skb->next);

	delta = htonl(oldlen + (skb->tail - skb->transport_header) +
		      skb->data_len);
	th->check = ~csum_fold((__force __wsum)((__force u32)th->check +
				(__force u32)delta));
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		th->check = csum_fold(csum_partial(skb_transport_header(skb),
						   thlen, skb->csum));

out:
	return segs;
}
EXPORT_SYMBOL(tcp_tso_segment);

struct sk_buff **tcp_gro_receive(struct sk_buff **head, struct sk_buff *skb)
{
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct tcphdr *th;
	struct tcphdr *th2;
	unsigned int len;
	unsigned int thlen;
	unsigned int flags;
	unsigned int mss = 1;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int i;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*th);
	th = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		goto out;

	hlen = off + thlen;
	if (skb_gro_header_hard(skb, hlen)) {
		th = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!th))
			goto out;
	}

	skb_gro_pull(skb, thlen);

	len = skb_gro_len(skb);
	flags = tcp_flag_word(th);

	for (; (p = *head); head = &p->next) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		th2 = tcp_hdr(p);

		if (*(u32 *)&th->source ^ *(u32 *)&th2->source) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		goto found;
	}

	goto out_check_final;

found:
	flush = NAPI_GRO_CB(p)->flush;
	flush |= flags & TCP_FLAG_CWR;
	flush |= (flags ^ tcp_flag_word(th2)) &
		  ~(TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH);
	flush |= th->ack_seq ^ th2->ack_seq;
	for (i = sizeof(*th); i < thlen; i += 4)
		flush |= *(u32 *)((u8 *)th + i) ^
			 *(u32 *)((u8 *)th2 + i);

	mss = skb_shinfo(p)->gso_size;

	flush |= (len - 1) >= mss;
	flush |= (ntohl(th2->seq) + skb_gro_len(p)) ^ ntohl(th->seq);

	if (flush || skb_gro_receive(head, skb)) {
		mss = 1;
		goto out_check_final;
	}

	p = *head;
	th2 = tcp_hdr(p);
	tcp_flag_word(th2) |= flags & (TCP_FLAG_FIN | TCP_FLAG_PSH);

out_check_final:
	flush = len < mss;
	flush |= flags & (TCP_FLAG_URG | TCP_FLAG_PSH | TCP_FLAG_RST |
			  TCP_FLAG_SYN | TCP_FLAG_FIN);

	if (p && (!NAPI_GRO_CB(skb)->same_flow || flush))
		pp = head;

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}
EXPORT_SYMBOL(tcp_gro_receive);

int tcp_gro_complete(struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	skb->csum_start = skb_transport_header(skb) - skb->head;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

	if (th->cwr)
		skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

	return 0;
}
EXPORT_SYMBOL(tcp_gro_complete);

#ifdef CONFIG_TCP_MD5SIG
static unsigned long tcp_md5sig_users;
static struct tcp_md5sig_pool **tcp_md5sig_pool;
static DEFINE_SPINLOCK(tcp_md5sig_pool_lock);

static void __tcp_free_md5sig_pool(struct tcp_md5sig_pool **pool)
{
	int cpu;
	for_each_possible_cpu(cpu) {
		struct tcp_md5sig_pool *p = *per_cpu_ptr(pool, cpu);
		if (p) {
			if (p->md5_desc.tfm)
				crypto_free_hash(p->md5_desc.tfm);
			kfree(p);
			p = NULL;
		}
	}
	free_percpu(pool);
}

void tcp_free_md5sig_pool(void)
{
	struct tcp_md5sig_pool **pool = NULL;

	spin_lock_bh(&tcp_md5sig_pool_lock);
	if (--tcp_md5sig_users == 0) {
		pool = tcp_md5sig_pool;
		tcp_md5sig_pool = NULL;
	}
	spin_unlock_bh(&tcp_md5sig_pool_lock);
	if (pool)
		__tcp_free_md5sig_pool(pool);
}

EXPORT_SYMBOL(tcp_free_md5sig_pool);

static struct tcp_md5sig_pool **__tcp_alloc_md5sig_pool(struct sock *sk)
{
	int cpu;
	struct tcp_md5sig_pool **pool;

	pool = alloc_percpu(struct tcp_md5sig_pool *);
	if (!pool)
		return NULL;

	for_each_possible_cpu(cpu) {
		struct tcp_md5sig_pool *p;
		struct crypto_hash *hash;

		p = kzalloc(sizeof(*p), sk->sk_allocation);
		if (!p)
			goto out_free;
		*per_cpu_ptr(pool, cpu) = p;

		hash = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
		if (!hash || IS_ERR(hash))
			goto out_free;

		p->md5_desc.tfm = hash;
	}
	return pool;
out_free:
	__tcp_free_md5sig_pool(pool);
	return NULL;
}

struct tcp_md5sig_pool **tcp_alloc_md5sig_pool(struct sock *sk)
{
	struct tcp_md5sig_pool **pool;
	int alloc = 0;

retry:
	spin_lock_bh(&tcp_md5sig_pool_lock);
	pool = tcp_md5sig_pool;
	if (tcp_md5sig_users++ == 0) {
		alloc = 1;
		spin_unlock_bh(&tcp_md5sig_pool_lock);
	} else if (!pool) {
		tcp_md5sig_users--;
		spin_unlock_bh(&tcp_md5sig_pool_lock);
		cpu_relax();
		goto retry;
	} else
		spin_unlock_bh(&tcp_md5sig_pool_lock);

	if (alloc) {
		/* we cannot hold spinlock here because this may sleep. */
		struct tcp_md5sig_pool **p = __tcp_alloc_md5sig_pool(sk);
		spin_lock_bh(&tcp_md5sig_pool_lock);
		if (!p) {
			tcp_md5sig_users--;
			spin_unlock_bh(&tcp_md5sig_pool_lock);
			return NULL;
		}
		pool = tcp_md5sig_pool;
		if (pool) {
			/* oops, it has already been assigned. */
			spin_unlock_bh(&tcp_md5sig_pool_lock);
			__tcp_free_md5sig_pool(p);
		} else {
			tcp_md5sig_pool = pool = p;
			spin_unlock_bh(&tcp_md5sig_pool_lock);
		}
	}
	return pool;
}

EXPORT_SYMBOL(tcp_alloc_md5sig_pool);

struct tcp_md5sig_pool *__tcp_get_md5sig_pool(int cpu)
{
	struct tcp_md5sig_pool **p;
	spin_lock_bh(&tcp_md5sig_pool_lock);
	p = tcp_md5sig_pool;
	if (p)
		tcp_md5sig_users++;
	spin_unlock_bh(&tcp_md5sig_pool_lock);
	return (p ? *per_cpu_ptr(p, cpu) : NULL);
}

EXPORT_SYMBOL(__tcp_get_md5sig_pool);

void __tcp_put_md5sig_pool(void)
{
	tcp_free_md5sig_pool();
}

EXPORT_SYMBOL(__tcp_put_md5sig_pool);

int tcp_md5_hash_header(struct tcp_md5sig_pool *hp,
			struct tcphdr *th)
{
	struct scatterlist sg;
	int err;

	__sum16 old_checksum = th->check;
	th->check = 0;
	/* options aren't included in the hash */
	sg_init_one(&sg, th, sizeof(struct tcphdr));
	err = crypto_hash_update(&hp->md5_desc, &sg, sizeof(struct tcphdr));
	th->check = old_checksum;
	return err;
}

EXPORT_SYMBOL(tcp_md5_hash_header);

int tcp_md5_hash_skb_data(struct tcp_md5sig_pool *hp,
			  struct sk_buff *skb, unsigned header_len)
{
	struct scatterlist sg;
	const struct tcphdr *tp = tcp_hdr(skb);
	struct hash_desc *desc = &hp->md5_desc;
	unsigned i;
	const unsigned head_data_len = skb_headlen(skb) > header_len ?
				       skb_headlen(skb) - header_len : 0;
	const struct skb_shared_info *shi = skb_shinfo(skb);

	sg_init_table(&sg, 1);

	sg_set_buf(&sg, ((u8 *) tp) + header_len, head_data_len);
	if (crypto_hash_update(desc, &sg, head_data_len))
		return 1;

	for (i = 0; i < shi->nr_frags; ++i) {
		const struct skb_frag_struct *f = &shi->frags[i];
		sg_set_page(&sg, f->page, f->size, f->page_offset);
		if (crypto_hash_update(desc, &sg, f->size))
			return 1;
	}

	return 0;
}

EXPORT_SYMBOL(tcp_md5_hash_skb_data);

int tcp_md5_hash_key(struct tcp_md5sig_pool *hp, struct tcp_md5sig_key *key)
{
	struct scatterlist sg;

	sg_init_one(&sg, key->key, key->keylen);
	return crypto_hash_update(&hp->md5_desc, &sg, key->keylen);
}

EXPORT_SYMBOL(tcp_md5_hash_key);

#endif

void tcp_done(struct sock *sk)
{
	if (sk->sk_state == TCP_SYN_SENT || sk->sk_state == TCP_SYN_RECV)
		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_ATTEMPTFAILS);

	tcp_set_state(sk, TCP_CLOSE);
	tcp_clear_xmit_timers(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk); /* 调用sock_def_wakeup() */
	else
		inet_csk_destroy_sock(sk);
}
EXPORT_SYMBOL_GPL(tcp_done);

extern struct tcp_congestion_ops tcp_reno;

static __initdata unsigned long thash_entries;
static int __init set_thash_entries(char *str)
{
	if (!str)
		return 0;
	thash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("thash_entries=", set_thash_entries);

void __init tcp_init(void)
{
	struct sk_buff *skb = NULL;
	unsigned long nr_pages, limit;
	int max_share, cnt;
	unsigned int i;

	BUILD_BUG_ON(sizeof(struct tcp_skb_cb) > sizeof(skb->cb));

	percpu_counter_init(&tcp_sockets_allocated, 0);
	percpu_counter_init(&tcp_orphan_count, 0);
	tcp_hashinfo.bind_bucket_cachep =
		kmem_cache_create("tcp_bind_bucket",
				  sizeof(struct inet_bind_bucket), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	/* Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	tcp_hashinfo.ehash =
		alloc_large_system_hash("TCP established",
					sizeof(struct inet_ehash_bucket),
					thash_entries,
					(totalram_pages >= 128 * 1024) ?
					13 : 15,
					0,
					&tcp_hashinfo.ehash_size,
					NULL,
					thash_entries ? 0 : 512 * 1024);
	tcp_hashinfo.ehash_size = 1U << tcp_hashinfo.ehash_size;
	for (i = 0; i < tcp_hashinfo.ehash_size; i++) {
		INIT_HLIST_NULLS_HEAD(&tcp_hashinfo.ehash[i].chain, i);
		INIT_HLIST_NULLS_HEAD(&tcp_hashinfo.ehash[i].twchain, i);
	}
	if (inet_ehash_locks_alloc(&tcp_hashinfo))
		panic("TCP: failed to alloc ehash_locks");
	tcp_hashinfo.bhash =
		alloc_large_system_hash("TCP bind",
					sizeof(struct inet_bind_hashbucket),
					tcp_hashinfo.ehash_size,
					(totalram_pages >= 128 * 1024) ?
					13 : 15,
					0,
					&tcp_hashinfo.bhash_size,
					NULL,
					64 * 1024);
	tcp_hashinfo.bhash_size = 1U << tcp_hashinfo.bhash_size;
	for (i = 0; i < tcp_hashinfo.bhash_size; i++) {
		spin_lock_init(&tcp_hashinfo.bhash[i].lock);
		INIT_HLIST_HEAD(&tcp_hashinfo.bhash[i].chain);
	}


	cnt = tcp_hashinfo.ehash_size;

	tcp_death_row.sysctl_max_tw_buckets = cnt / 2;
	sysctl_tcp_max_orphans = cnt / 2;
	sysctl_max_syn_backlog = max(128, cnt / 256);

	/* Set the pressure threshold to be a fraction of global memory that
	 * is up to 1/2 at 256 MB, decreasing toward zero with the amount of
	 * memory, with a floor of 128 pages, and a ceiling that prevents an
	 * integer overflow.
	 */
	nr_pages = totalram_pages - totalhigh_pages;
	limit = min(nr_pages, 1UL<<(28-PAGE_SHIFT)) >> (20-PAGE_SHIFT);
	limit = (limit * (nr_pages >> (20-PAGE_SHIFT))) >> (PAGE_SHIFT-11);
	limit = max(limit, 128UL);
	limit = min(limit, INT_MAX * 4UL / 3 / 2);
	sysctl_tcp_mem[0] = limit / 4 * 3;
	sysctl_tcp_mem[1] = limit;
	sysctl_tcp_mem[2] = sysctl_tcp_mem[0] * 2;

	/* Set per-socket limits to no more than 1/128 the pressure threshold */
	limit = ((unsigned long)sysctl_tcp_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL*1024*1024, limit);

	sysctl_tcp_wmem[0] = SK_MEM_QUANTUM;
	sysctl_tcp_wmem[1] = 16*1024;
	sysctl_tcp_wmem[2] = max(64*1024, max_share);

	sysctl_tcp_rmem[0] = SK_MEM_QUANTUM;
	sysctl_tcp_rmem[1] = 87380;
	sysctl_tcp_rmem[2] = max(87380, max_share);

	printk(KERN_INFO "TCP: Hash tables configured "
	       "(established %d bind %d)\n",
	       tcp_hashinfo.ehash_size, tcp_hashinfo.bhash_size);

	tcp_register_congestion_control(&tcp_reno);
}

EXPORT_SYMBOL(tcp_close);
EXPORT_SYMBOL(tcp_disconnect);
EXPORT_SYMBOL(tcp_getsockopt);
EXPORT_SYMBOL(tcp_ioctl);
EXPORT_SYMBOL(tcp_poll);
EXPORT_SYMBOL(tcp_read_sock);
EXPORT_SYMBOL(tcp_recvmsg);
EXPORT_SYMBOL(tcp_sendmsg);
EXPORT_SYMBOL(tcp_splice_read);
EXPORT_SYMBOL(tcp_sendpage);
EXPORT_SYMBOL(tcp_setsockopt);
EXPORT_SYMBOL(tcp_shutdown);
