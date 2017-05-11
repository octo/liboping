/**
 * Object oriented C module to send ICMP and ICMPv6 `echo's.
 * Copyright (C) 2006-2017  Florian octo Forster <ff at octo.it>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <inttypes.h>
# include <errno.h>
# include <assert.h>
#else
# error "You don't have the standard C99 header files installed"
#endif /* STDC_HEADERS */

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#if HAVE_FCNTL_H
# include <fcntl.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#if HAVE_NETDB_H
# include <netdb.h>
#endif

#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif
#if HAVE_NETINET_IP_ICMP_H
# include <netinet/ip_icmp.h>
#endif
#ifdef HAVE_NETINET_IP_VAR_H
# include <netinet/ip_var.h>
#endif
#if HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
#endif
#if HAVE_NETINET_ICMP6_H
# include <netinet/icmp6.h>
#endif

#include "oping.h"

#if WITH_DEBUG
# define dprintf(...) printf ("%s[%4i]: %-20s: ", __FILE__, __LINE__, __FUNCTION__); printf (__VA_ARGS__)
#else
# define dprintf(...) /**/
#endif

#define PING_ERRMSG_LEN 256
#define PING_TABLE_LEN 5381

struct pinghost
{
	/* username: name passed in by the user */
	char                    *username;
	/* hostname: name returned by the reverse lookup */
	char                    *hostname;
	struct sockaddr_storage *addr;
	socklen_t                addrlen;
	int                      addrfamily;
	int                      ident;
	int                      sequence;
	struct timeval          *timer;
	double                   latency;
	uint32_t                 dropped;
	int                      recv_ttl;
	uint8_t                  recv_qos;
	char                    *data;

	void                    *context;

	struct pinghost         *next;
	struct pinghost         *table_next;
};

struct pingobj
{
	double                   timeout;
	int                      ttl;
	int                      addrfamily;
	uint8_t                  qos;
	char                    *data;

	int                      fd4;
	int                      fd6;

	struct sockaddr         *srcaddr;
	socklen_t                srcaddrlen;

	char                    *device;

	char                    set_mark;
	int                     mark;

	char                     errmsg[PING_ERRMSG_LEN];

	pinghost_t              *head;
	pinghost_t              *table[PING_TABLE_LEN];
};

/*
 * private (static) functions
 */
/* Even though Posix requires "strerror_r" to return an "int",
 * some systems (e.g. the GNU libc) return a "char *" _and_
 * ignore the second argument ... -tokkee */
static char *sstrerror (int errnum, char *buf, size_t buflen)
{
	buf[0] = 0;

#if !HAVE_STRERROR_R
	{
		snprintf (buf, buflen, "Error %i (%#x)", errnum, errnum);
	}
/* #endif !HAVE_STRERROR_R */

#elif STRERROR_R_CHAR_P
	{
		char *temp;
		temp = strerror_r (errnum, buf, buflen);
		if (buf[0] == 0)
		{
			if ((temp != NULL) && (temp != buf) && (temp[0] != 0))
				strncpy (buf, temp, buflen);
			else
				strncpy (buf, "strerror_r did not return "
						"an error message", buflen);
		}
	}
/* #endif STRERROR_R_CHAR_P */

#else
	if (strerror_r (errnum, buf, buflen) != 0)
	{
		snprintf (buf, buflen, "Error %i (%#x); "
				"Additionally, strerror_r failed.",
				errnum, errnum);
	}
#endif /* STRERROR_R_CHAR_P */

	buf[buflen - 1] = 0;

	return (buf);
} /* char *sstrerror */

static void ping_set_error (pingobj_t *obj, const char *function,
	       	const char *message)
{
	snprintf (obj->errmsg, sizeof (obj->errmsg),
			"%s: %s", function, message);
	obj->errmsg[sizeof (obj->errmsg) - 1] = 0;
}

static void ping_set_errno (pingobj_t *obj, int error_number)
{
	sstrerror (error_number, obj->errmsg, sizeof (obj->errmsg));
}

static int ping_timeval_add (struct timeval *tv1, struct timeval *tv2,
		struct timeval *res)
{
	res->tv_sec  = tv1->tv_sec  + tv2->tv_sec;
	res->tv_usec = tv1->tv_usec + tv2->tv_usec;

	while (res->tv_usec > 1000000)
	{
		res->tv_usec -= 1000000;
		res->tv_sec++;
	}

	return (0);
}

static int ping_timeval_sub (struct timeval *tv1, struct timeval *tv2,
		struct timeval *res)
{
	if ((tv1->tv_sec < tv2->tv_sec)
			|| ((tv1->tv_sec == tv2->tv_sec)
				&& (tv1->tv_usec < tv2->tv_usec)))
		return (-1);

	res->tv_sec  = tv1->tv_sec  - tv2->tv_sec;
	res->tv_usec = tv1->tv_usec - tv2->tv_usec;

	assert ((res->tv_sec > 0) || ((res->tv_sec == 0) && (res->tv_usec >= 0)));

	while (res->tv_usec < 0)
	{
		res->tv_usec += 1000000;
		res->tv_sec--;
	}

	return (0);
}

static uint16_t ping_icmp4_checksum (char *buf, size_t len)
{
	uint32_t sum = 0;
	uint16_t ret = 0;

	uint16_t *ptr;

	for (ptr = (uint16_t *) buf; len > 1; ptr++, len -= 2)
		sum += *ptr;

	if (len == 1)
	{
		*(char *) &ret = *(char *) ptr;
		sum += ret;
	}

	/* Do this twice to get all possible carries.. */
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = (sum >> 16) + (sum & 0xFFFF);

	ret = ~sum;

	return (ret);
}

static pinghost_t *ping_receive_ipv4 (pingobj_t *obj, char *buffer,
		size_t buffer_len)
{
	struct ip *ip_hdr;
	struct icmp *icmp_hdr;

	size_t ip_hdr_len;

	uint16_t recv_checksum;
	uint16_t calc_checksum;

	uint16_t ident;
	uint16_t seq;

	pinghost_t *ptr;

	if (buffer_len < sizeof (struct ip))
		return (NULL);

	ip_hdr     = (struct ip *) buffer;
	ip_hdr_len = ip_hdr->ip_hl << 2;

	if (buffer_len < ip_hdr_len)
		return (NULL);

	buffer     += ip_hdr_len;
	buffer_len -= ip_hdr_len;

	if (buffer_len < ICMP_MINLEN)
		return (NULL);

	icmp_hdr = (struct icmp *) buffer;
	if (icmp_hdr->icmp_type != ICMP_ECHOREPLY)
	{
		dprintf ("Unexpected ICMP type: %"PRIu8"\n", icmp_hdr->icmp_type);
		return (NULL);
	}

	recv_checksum = icmp_hdr->icmp_cksum;
	/* This writes to buffer. */
	icmp_hdr->icmp_cksum = 0;
	calc_checksum = ping_icmp4_checksum (buffer, buffer_len);

	if (recv_checksum != calc_checksum)
	{
		dprintf ("Checksum missmatch: Got 0x%04"PRIx16", "
				"calculated 0x%04"PRIx16"\n",
				recv_checksum, calc_checksum);
		return (NULL);
	}

	ident = ntohs (icmp_hdr->icmp_id);
	seq   = ntohs (icmp_hdr->icmp_seq);

	for (ptr = obj->table[ident % PING_TABLE_LEN];
			ptr != NULL; ptr = ptr->table_next)
	{
		dprintf ("hostname = %s, ident = 0x%04x, seq = %i\n",
				ptr->hostname, ptr->ident, ((ptr->sequence - 1) & 0xFFFF));

		if (ptr->addrfamily != AF_INET)
			continue;

		if (!timerisset (ptr->timer))
			continue;

		if (ptr->ident != ident)
			continue;

		if (((ptr->sequence - 1) & 0xFFFF) != seq)
			continue;

		dprintf ("Match found: hostname = %s, ident = 0x%04"PRIx16", "
				"seq = %"PRIu16"\n",
				ptr->hostname, ident, seq);

		break;
	}

	if (ptr == NULL)
	{
		dprintf ("No match found for ident = 0x%04"PRIx16", seq = %"PRIu16"\n",
				ident, seq);
	}

	if (ptr != NULL){
		ptr->recv_ttl = (int)     ip_hdr->ip_ttl;
		ptr->recv_qos = (uint8_t) ip_hdr->ip_tos;
	}
	return (ptr);
}

#ifndef ICMP6_ECHO_REQUEST
# ifdef ICMP6_ECHO /* AIX netinet/ip6_icmp.h */
#  define ICMP6_ECHO_REQUEST ICMP6_ECHO
# else
#  define ICMP6_ECHO_REQUEST 128
# endif
#endif

#ifndef ICMP6_ECHO_REPLY
# ifdef ICMP6_ECHOREPLY /* AIX netinet/ip6_icmp.h */
#  define ICMP6_ECHO_REPLY ICMP6_ECHOREPLY
# else
#  define ICMP6_ECHO_REPLY 129
# endif
#endif

static pinghost_t *ping_receive_ipv6 (pingobj_t *obj, char *buffer,
		size_t buffer_len)
{
	struct icmp6_hdr *icmp_hdr;

	uint16_t ident;
	uint16_t seq;

	pinghost_t *ptr;

	if (buffer_len < ICMP_MINLEN)
		return (NULL);

	icmp_hdr = (struct icmp6_hdr *) buffer;
	buffer     += ICMP_MINLEN;
	buffer_len -= ICMP_MINLEN;

	if (icmp_hdr->icmp6_type != ICMP6_ECHO_REPLY)
	{
		dprintf ("Unexpected ICMP type: %02x\n", icmp_hdr->icmp6_type);
		return (NULL);
	}

	if (icmp_hdr->icmp6_code != 0)
	{
		dprintf ("Unexpected ICMP code: %02x\n", icmp_hdr->icmp6_code);
		return (NULL);
	}

	ident = ntohs (icmp_hdr->icmp6_id);
	seq   = ntohs (icmp_hdr->icmp6_seq);

	/* We have to iterate over all hosts, since ICMPv6 packets may
	 * be received on any raw v6 socket. */
	for (ptr = obj->head; ptr != NULL; ptr = ptr->next)
	{
		dprintf ("hostname = %s, ident = 0x%04x, seq = %i\n",
				ptr->hostname, ptr->ident, ((ptr->sequence - 1) & 0xFFFF));

		if (ptr->addrfamily != AF_INET6)
			continue;

		if (!timerisset (ptr->timer))
			continue;

		if (ptr->ident != ident)
			continue;

		if (((ptr->sequence - 1) & 0xFFFF) != seq)
			continue;

		dprintf ("Match found: hostname = %s, ident = 0x%04"PRIx16", "
				"seq = %"PRIu16"\n",
				ptr->hostname, ident, seq);

		break;
	}

	if (ptr == NULL)
	{
		dprintf ("No match found for ident = 0x%04"PRIx16", "
				"seq = %"PRIu16"\n",
				ident, seq);
	}

	return (ptr);
}

static int ping_receive_one (pingobj_t *obj, struct timeval *now, int addrfam)
{
	int fd = addrfam == AF_INET6 ? obj->fd6 : obj->fd4;
	struct timeval diff, pkt_now = *now;
	pinghost_t *host = NULL;
	int recv_ttl;
	uint8_t recv_qos;

	/*
	 * Set up the receive buffer..
	 */
	struct msghdr msghdr;
	struct cmsghdr *cmsg;
	char payload_buffer[4096];
	ssize_t payload_buffer_len;
	char control_buffer[4096];
	struct iovec payload_iovec;

	memset (&payload_iovec, 0, sizeof (payload_iovec));
	payload_iovec.iov_base = payload_buffer;
	payload_iovec.iov_len = sizeof (payload_buffer);

	memset (&msghdr, 0, sizeof (msghdr));
	/* unspecified source address */
	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	/* output buffer vector, see readv(2) */
	msghdr.msg_iov = &payload_iovec;
	msghdr.msg_iovlen = 1;
	/* output buffer for control messages */
	msghdr.msg_control = control_buffer;
	msghdr.msg_controllen = sizeof (control_buffer);
	/* flags; this is an output only field.. */
	msghdr.msg_flags = 0;
#ifdef MSG_XPG4_2
	msghdr.msg_flags |= MSG_XPG4_2;
#endif

	payload_buffer_len = recvmsg (fd, &msghdr, /* flags = */ 0);
	if (payload_buffer_len < 0)
	{
#if WITH_DEBUG
		char errbuf[PING_ERRMSG_LEN];
		dprintf ("recvfrom: %s\n",
				sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
		return (-1);
	}
	dprintf ("Read %zi bytes from fd = %i\n", payload_buffer_len, fd);

	/* Iterate over all auxiliary data in msghdr */
	recv_ttl = -1;
	recv_qos = 0;
	for (cmsg = CMSG_FIRSTHDR (&msghdr); /* {{{ */
			cmsg != NULL;
			cmsg = CMSG_NXTHDR (&msghdr, cmsg))
	{
		if (cmsg->cmsg_level == SOL_SOCKET)
		{
#ifdef SO_TIMESTAMP
			if (cmsg->cmsg_type == SO_TIMESTAMP)
				memcpy (&pkt_now, CMSG_DATA (cmsg), sizeof (pkt_now));
#endif /* SO_TIMESTAMP */
		}
		else if (addrfam == AF_INET) /* {{{ */
		{
			if (cmsg->cmsg_level != IPPROTO_IP)
				continue;

			if (cmsg->cmsg_type == IP_TOS)
			{
				memcpy (&recv_qos, CMSG_DATA (cmsg),
						sizeof (recv_qos));
				dprintf ("TOSv4 = 0x%02"PRIx8";\n", recv_qos);
			} else
			if (cmsg->cmsg_type == IP_TTL)
			{
				memcpy (&recv_ttl, CMSG_DATA (cmsg),
						sizeof (recv_ttl));
				dprintf ("TTLv4 = %i;\n", recv_ttl);
			}
			else
			{
				dprintf ("Not handling option %i.\n",
						cmsg->cmsg_type);
			}
		} /* }}} */
		else if (addrfam == AF_INET6) /* {{{ */
		{
			if (cmsg->cmsg_level != IPPROTO_IPV6)
				continue;

			if (cmsg->cmsg_type == IPV6_TCLASS)
			{
				memcpy (&recv_qos, CMSG_DATA (cmsg),
						sizeof (recv_qos));
				dprintf ("TOSv6 = 0x%02"PRIx8";\n", recv_qos);
			} else
#ifdef IPV6_HOPLIMIT
			if (cmsg->cmsg_type == IPV6_HOPLIMIT)
			{
				memcpy (&recv_ttl, CMSG_DATA (cmsg),
						sizeof (recv_ttl));
				dprintf ("TTLv6 = %i;\n", recv_ttl);
			}
			else
#endif
#ifdef IPV6_UNICAST_HOPS
			if (cmsg->cmsg_type == IPV6_UNICAST_HOPS)
			{
				memcpy (&recv_ttl, CMSG_DATA (cmsg),
						sizeof (recv_ttl));
				dprintf ("TTLv6 = %i;\n", recv_ttl);
			}
			else
#endif
#ifdef IPV6_MULTICAST_HOPS
			if (cmsg->cmsg_type == IPV6_MULTICAST_HOPS)
			{
				memcpy (&recv_ttl, CMSG_DATA (cmsg),
						sizeof (recv_ttl));
				dprintf ("TTLv6 = %i;\n", recv_ttl);
			}
			else
#endif
			{
				dprintf ("Not handling option %i.\n",
						cmsg->cmsg_type);
			}
		} /* }}} */
		else
		{
			dprintf ("Don't know how to handle "
					"unknown protocol %i.\n",
					cmsg->cmsg_level);
		}
	} /* }}} for (cmsg) */

	if (addrfam == AF_INET)
	{
		host = ping_receive_ipv4 (obj, payload_buffer, payload_buffer_len);
		if (host == NULL)
			return (-1);
	}
	else if (addrfam == AF_INET6)
	{
		host = ping_receive_ipv6 (obj, payload_buffer, payload_buffer_len);
		if (host == NULL)
			return (-1);
	}
	else
	{
		dprintf ("ping_receive_one: Unknown address family %i.\n",
				addrfam);
		return (-1);
	}

	dprintf ("rcvd: %12i.%06i\n",
			(int) pkt_now.tv_sec,
			(int) pkt_now.tv_usec);
	dprintf ("sent: %12i.%06i\n",
			(int) host->timer->tv_sec,
			(int) host->timer->tv_usec);

	if (ping_timeval_sub (&pkt_now, host->timer, &diff) < 0)
	{
		timerclear (host->timer);
		return (-1);
	}

	dprintf ("diff: %12i.%06i\n",
			(int) diff.tv_sec,
			(int) diff.tv_usec);

	if (recv_ttl >= 0)
		host->recv_ttl = recv_ttl;
	host->recv_qos = recv_qos;

	host->latency  = ((double) diff.tv_usec) / 1000.0;
	host->latency += ((double) diff.tv_sec)  * 1000.0;

	timerclear (host->timer);

	return (0);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Sending functions:                                                        *
 *                                                                           *
 * ping_send_all                                                             *
 * +-> ping_send_one_ipv4                                                    *
 * `-> ping_send_one_ipv6                                                    *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
static ssize_t ping_sendto (pingobj_t *obj, pinghost_t *ph,
		const void *buf, size_t buflen, int fd)
{
	ssize_t ret;

	if (gettimeofday (ph->timer, NULL) == -1)
	{
		timerclear (ph->timer);
		return (-1);
	}

	ret = sendto (fd, buf, buflen, 0,
			(struct sockaddr *) ph->addr, ph->addrlen);

	if (ret < 0)
	{
#if defined(EHOSTUNREACH)
		if (errno == EHOSTUNREACH)
			return (0);
#endif
#if defined(ENETUNREACH)
		if (errno == ENETUNREACH)
			return (0);
#endif
		ping_set_errno (obj, errno);
	}

	return (ret);
}

static int ping_send_one_ipv4 (pingobj_t *obj, pinghost_t *ph, int fd)
{
	struct icmp *icmp4;
	int status;

	char   buf[4096] = {0};
	size_t buflen;

	char *data;
	size_t datalen;

	dprintf ("ph->hostname = %s\n", ph->hostname);

	icmp4 = (struct icmp *) buf;
	*icmp4 = (struct icmp) {
		.icmp_type = ICMP_ECHO,
		.icmp_id   = htons (ph->ident),
		.icmp_seq  = htons (ph->sequence),
	};

	datalen = strlen (ph->data);
	buflen = ICMP_MINLEN + datalen;
	if (sizeof (buf) < buflen)
		return (EINVAL);

	data  = buf + ICMP_MINLEN;
	memcpy (data, ph->data, datalen);

	icmp4->icmp_cksum = ping_icmp4_checksum (buf, buflen);

	dprintf ("Sending ICMPv4 package with ID 0x%04x\n", ph->ident);

	status = ping_sendto (obj, ph, buf, buflen, fd);
	if (status < 0)
	{
		perror ("ping_sendto");
		return (-1);
	}

	dprintf ("sendto: status = %i\n", status);

	return (0);
}

static int ping_send_one_ipv6 (pingobj_t *obj, pinghost_t *ph, int fd)
{
	struct icmp6_hdr *icmp6;
	int status;

	char buf[4096] = {0};
	int  buflen;

	char *data;
	int   datalen;

	dprintf ("ph->hostname = %s\n", ph->hostname);

	icmp6 = (struct icmp6_hdr *) buf;
	*icmp6 = (struct icmp6_hdr) {
		.icmp6_type  = ICMP6_ECHO_REQUEST,
		.icmp6_id    = htons (ph->ident),
		.icmp6_seq   = htons (ph->sequence),
	};

	datalen = strlen (ph->data);
	buflen = sizeof (*icmp6) + datalen;
	if (sizeof (buf) < buflen)
		return (EINVAL);

	data  = buf + ICMP_MINLEN;
	memcpy (data, ph->data, datalen);

	/* The checksum will be calculated by the TCP/IP stack. */

	dprintf ("Sending ICMPv6 package with ID 0x%04x\n", ph->ident);

	status = ping_sendto (obj, ph, buf, buflen, fd);
	if (status < 0)
	{
		perror ("ping_sendto");
		return (-1);
	}

	dprintf ("sendto: status = %i\n", status);

	return (0);
}

static int ping_send_one (pingobj_t *obj, pinghost_t *ptr, int fd)
{
	if (gettimeofday (ptr->timer, NULL) == -1)
	{
		/* start timer.. The GNU `ping6' starts the timer before
		 * sending the packet, so I will do that too */
#if WITH_DEBUG
		char errbuf[PING_ERRMSG_LEN];
		dprintf ("gettimeofday: %s\n",
				sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
		timerclear (ptr->timer);
		return (-1);
	}
	else
	{
		dprintf ("timer set for hostname = %s\n", ptr->hostname);
	}

	if (ptr->addrfamily == AF_INET6)
	{
		dprintf ("Sending ICMPv6 echo request to `%s'\n", ptr->hostname);
		if (ping_send_one_ipv6 (obj, ptr, fd) != 0)
		{
			timerclear (ptr->timer);
			return (-1);
		}
	}
	else if (ptr->addrfamily == AF_INET)
	{
		dprintf ("Sending ICMPv4 echo request to `%s'\n", ptr->hostname);
		if (ping_send_one_ipv4 (obj, ptr, fd) != 0)
		{
			timerclear (ptr->timer);
			return (-1);
		}
	}
	else /* this should not happen */
	{
		dprintf ("Unknown address family: %i\n", ptr->addrfamily);
		timerclear (ptr->timer);
		return (-1);
	}

	ptr->sequence++;

	return (0);
}

/*
 * Set the TTL of a socket protocol independently.
 */
static int ping_set_ttl (pingobj_t *obj, int ttl)
{
	int ret = 0;
	char errbuf[PING_ERRMSG_LEN];

	if (obj->fd4 != -1)
	{
		if (setsockopt (obj->fd4, IPPROTO_IP, IP_TTL,
				&ttl, sizeof (ttl)))
		{
			ret = errno;
			ping_set_error (obj, "ping_set_ttl",
					sstrerror (ret, errbuf, sizeof (errbuf)));
			dprintf ("Setting TTLv4 failed: %s\n", errbuf);
		}
	}

	if (obj->fd6 != -1)
	{
		dprintf ("Setting TTLv6 to %i\n", ttl);
		if (setsockopt (obj->fd6, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&ttl, sizeof (ttl)))
		{
			ret = errno;
			ping_set_error (obj, "ping_set_ttl",
					sstrerror (ret, errbuf, sizeof (errbuf)));
			dprintf ("Setting TTLv6 failed: %s\n", errbuf);
		}
	}

	return (ret);
}

/*
 * Set the TOS of a socket protocol independently.
 *
 * Using SOL_SOCKET / SO_PRIORITY might be a protocol independent way to
 * set this. See socket(7) for details.
 */
static int ping_set_qos (pingobj_t *obj, uint8_t qos)
{
	int ret = 0;
	char errbuf[PING_ERRMSG_LEN];

	if (obj->fd4 != -1)
	{
		dprintf ("Setting TP_TOS to %#04"PRIx8"\n", qos);
		if (setsockopt (obj->fd4, IPPROTO_IP, IP_TOS,
				&qos, sizeof (qos)))
		{
			ret = errno;
			ping_set_error (obj, "ping_set_qos",
					sstrerror (ret, errbuf, sizeof (errbuf)));
			dprintf ("Setting TP_TOS failed: %s\n", errbuf);
		}
	}

	if (obj->fd6 != -1)
	{
		/* IPV6_TCLASS requires an "int". */
		int tmp = (int) qos;

		dprintf ("Setting IPV6_TCLASS to %#04"PRIx8" (%i)\n", qos, tmp);
		if (setsockopt (obj->fd6, IPPROTO_IPV6, IPV6_TCLASS,
			&tmp, sizeof (tmp)))
		{
			ret = errno;
			ping_set_error (obj, "ping_set_qos",
					sstrerror (ret, errbuf, sizeof (errbuf)));
			dprintf ("Setting IPV6_TCLASS failed: %s\n", errbuf);
		}
	}

	return (ret);
}

static int ping_get_ident (void)
{
	int fd;
	static int did_seed = 0;

	int retval;

	if (did_seed == 0)
	{
		if ((fd = open ("/dev/urandom", O_RDONLY)) != -1)
		{
			unsigned int seed;

			if (read (fd, &seed, sizeof (seed)) != -1)
			{
				did_seed = 1;
				dprintf ("Random seed:   %#x\n", seed);
				srandom (seed);
			}

			close (fd);
		}
#if WITH_DEBUG
		else
		{
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("open (/dev/urandom): %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
		}
#endif
	}

	retval = (int) random ();

	dprintf ("Random number: %#x\n", retval);

	return (retval);
}

static pinghost_t *ping_alloc (void)
{
	pinghost_t *ph;
	size_t      ph_size;

	ph_size = sizeof (pinghost_t)
		+ sizeof (struct sockaddr_storage)
		+ sizeof (struct timeval);

	ph = (pinghost_t *) malloc (ph_size);
	if (ph == NULL)
		return (NULL);

	memset (ph, '\0', ph_size);

	ph->timer   = (struct timeval *) (ph + 1);
	ph->addr    = (struct sockaddr_storage *) (ph->timer + 1);

	ph->addrlen = sizeof (struct sockaddr_storage);
	ph->latency = -1.0;
	ph->dropped = 0;
	ph->ident   = ping_get_ident () & 0xFFFF;

	return (ph);
}

static void ping_free (pinghost_t *ph)
{
	if (ph == NULL)
		return;

	free (ph->username);
	free (ph->hostname);
	free (ph->data);

	free (ph);
}

/* ping_open_socket opens, initializes and returns a new raw socket to use for
 * ICMPv4 or ICMPv6 packets. addrfam must be either AF_INET or AF_INET6. On
 * error, -1 is returned and obj->errmsg is set appropriately. */
static int ping_open_socket(pingobj_t *obj, int addrfam)
{
	int fd;
	if (addrfam == AF_INET6)
	{
		fd = socket(addrfam, SOCK_RAW, IPPROTO_ICMPV6);
	}
	else if (addrfam == AF_INET)
	{
		fd = socket(addrfam, SOCK_RAW, IPPROTO_ICMP);
	}
	else /* this should not happen */
	{
		ping_set_error (obj, "ping_open_socket", "Unknown address family");
		dprintf ("Unknown address family: %i\n", addrfam);
		return -1;
	}

	if (fd == -1)
	{
		ping_set_errno (obj, errno);
#if WITH_DEBUG
		char errbuf[PING_ERRMSG_LEN];
		dprintf ("socket: %s\n",
				sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
		return -1;
	}
	else if (fd >= FD_SETSIZE)
	{
		ping_set_errno (obj, EMFILE);
		dprintf ("socket(2) returned file descriptor %d, which is above the file "
			 "descriptor limit for select(2) (FD_SETSIZE = %d)\n",
			 fd, FD_SETSIZE);
		close (fd);
		return -1;
	}

	if (obj->srcaddr != NULL)
	{
		assert (obj->srcaddrlen > 0);
		assert (obj->srcaddrlen <= sizeof (struct sockaddr_storage));

		if (bind (fd, obj->srcaddr, obj->srcaddrlen) == -1)
		{
			ping_set_errno (obj, errno);
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("bind: %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			close (fd);
			return -1;
		}
	}

#ifdef SO_BINDTODEVICE
	if (obj->device != NULL)
	{
		if (setsockopt (fd, SOL_SOCKET, SO_BINDTODEVICE,
				obj->device, strlen (obj->device) + 1) != 0)
		{
			ping_set_errno (obj, errno);
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("setsockopt (SO_BINDTODEVICE): %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			close (fd);
			return -1;
		}
	}
#endif /* SO_BINDTODEVICE */
#ifdef SO_MARK
	if (obj->set_mark)
	{
		if (setsockopt(fd, SOL_SOCKET, SO_MARK,
				&obj->mark, sizeof(obj->mark)) != 0)
		{
			ping_set_errno (obj, errno);
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("setsockopt (SO_MARK): %s\n",
				 sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			close (fd);
			return -1;
		}
	}
#endif
#ifdef SO_TIMESTAMP
	if (1) /* {{{ */
	{
		int status = setsockopt (fd, SOL_SOCKET, SO_TIMESTAMP,
		                         &(int){1}, sizeof(int));
		if (status != 0)
		{
			ping_set_errno (obj, errno);
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("setsockopt (SO_TIMESTAMP): %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			close (fd);
			return -1;
		}
	} /* }}} if (1) */
#endif /* SO_TIMESTAMP */

	if (addrfam == AF_INET)
	{
#ifdef IP_RECVTOS
		/* Enable receiving the TOS field */
		setsockopt (fd, IPPROTO_IP, IP_RECVTOS, &(int){1}, sizeof(int));
#endif /* IP_RECVTOS */

		/* Enable receiving the TTL field */
		setsockopt (fd, IPPROTO_IP, IP_RECVTTL, &(int){1}, sizeof(int));
	}
#if defined(IPV6_RECVHOPLIMIT) || defined(IPV6_RECVTCLASS)
	else if (addrfam == AF_INET6)
	{
# if defined(IPV6_RECVHOPLIMIT)
		/* For details see RFC 3542, section 6.3. */
		setsockopt (fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
		            &(int){1}, sizeof(int));
# endif /* IPV6_RECVHOPLIMIT */

# if defined(IPV6_RECVTCLASS)
		/* For details see RFC 3542, section 6.5. */
		setsockopt (fd, IPPROTO_IPV6, IPV6_RECVTCLASS,
		            &(int){1}, sizeof(int));
# endif /* IPV6_RECVTCLASS */
	}
#endif /* IPV6_RECVHOPLIMIT || IPV6_RECVTCLASS */

	return fd;
}

/*
 * public methods
 */
const char *ping_get_error (pingobj_t *obj)
{
	if (obj == NULL)
		return (NULL);
	return (obj->errmsg);
}

pingobj_t *ping_construct (void)
{
	pingobj_t *obj;

	if ((obj = malloc (sizeof (*obj))) == NULL)
		return (NULL);
	memset (obj, 0, sizeof (*obj));

	obj->timeout    = PING_DEF_TIMEOUT;
	obj->ttl        = PING_DEF_TTL;
	obj->addrfamily = PING_DEF_AF;
	obj->data       = strdup (PING_DEF_DATA);
	obj->qos        = 0;
	obj->fd4        = -1;
	obj->fd6        = -1;

	return (obj);
}

void ping_destroy (pingobj_t *obj)
{
	pinghost_t *current;

	if (obj == NULL)
		return;

	current = obj->head;

	while (current != NULL)
	{
		pinghost_t *next = current->next;
		ping_free (current);
		current = next;
	}

	free (obj->data);
	free (obj->srcaddr);
	free (obj->device);

	if (obj->fd4 != -1)
		close(obj->fd4);

	if (obj->fd6 != -1)
		close(obj->fd6);

	free (obj);

	return;
}

int ping_setopt (pingobj_t *obj, int option, void *value)
{
	int ret = 0;

	if ((obj == NULL) || (value == NULL))
		return (-1);

	switch (option)
	{
		case PING_OPT_QOS:
		{
			obj->qos = *((uint8_t *) value);
			ret = ping_set_qos (obj, obj->qos);
			break;
		}

		case PING_OPT_TIMEOUT:
			obj->timeout = *((double *) value);
			if (obj->timeout < 0.0)
			{
				obj->timeout = PING_DEF_TIMEOUT;
				ret = -1;
			}
			break;

		case PING_OPT_TTL:
			ret = *((int *) value);
			if ((ret < 1) || (ret > 255))
			{
				obj->ttl = PING_DEF_TTL;
				ret = -1;
			}
			else
			{
				obj->ttl = ret;
				ret = ping_set_ttl (obj, obj->ttl);
			}
			break;

		case PING_OPT_AF:
			obj->addrfamily = *((int *) value);
			if ((obj->addrfamily != AF_UNSPEC)
					&& (obj->addrfamily != AF_INET)
					&& (obj->addrfamily != AF_INET6))
			{
				obj->addrfamily = PING_DEF_AF;
				ret = -1;
			}
			if (obj->srcaddr != NULL)
			{
				free (obj->srcaddr);
				obj->srcaddr = NULL;
			}
			break;

		case PING_OPT_DATA:
			if (obj->data != NULL)
			{
				free (obj->data);
				obj->data = NULL;
			}
			obj->data = strdup ((const char *) value);
			break;

		case PING_OPT_SOURCE:
		{
			char            *hostname = (char *) value;
			struct addrinfo  ai_hints;
			struct addrinfo *ai_list;
			int              status;
#if WITH_DEBUG
			if (obj->addrfamily != AF_UNSPEC)
			{
				dprintf ("Resetting obj->addrfamily to AF_UNSPEC.\n");
			}
#endif
			memset ((void *) &ai_hints, '\0', sizeof (ai_hints));
			ai_hints.ai_family = obj->addrfamily = AF_UNSPEC;
#if defined(AI_ADDRCONFIG)
			ai_hints.ai_flags = AI_ADDRCONFIG;
#endif
			status = getaddrinfo (hostname, NULL, &ai_hints, &ai_list);
			if (status != 0)
			{
#if defined(EAI_SYSTEM)
				char errbuf[PING_ERRMSG_LEN];
#endif
				ping_set_error (obj, "getaddrinfo",
#if defined(EAI_SYSTEM)
						(status == EAI_SYSTEM)
						? sstrerror (errno, errbuf, sizeof (errbuf)) :
#endif
						gai_strerror (status));
				ret = -1;
				break;
			}
#if WITH_DEBUG
			if (ai_list->ai_next != NULL)
			{
				dprintf ("hostname = `%s' is ambiguous.\n", hostname);
			}
#endif
			if (obj->srcaddr == NULL)
			{
				obj->srcaddrlen = 0;
				obj->srcaddr = malloc (sizeof (struct sockaddr_storage));
				if (obj->srcaddr == NULL)
				{
					ping_set_errno (obj, errno);
					ret = -1;
					freeaddrinfo (ai_list);
					break;
				}
			}
			memset ((void *) obj->srcaddr, 0, sizeof (struct sockaddr_storage));
			assert (ai_list->ai_addrlen <= sizeof (struct sockaddr_storage));
			memcpy ((void *) obj->srcaddr, (const void *) ai_list->ai_addr,
					ai_list->ai_addrlen);
			obj->srcaddrlen = ai_list->ai_addrlen;
			obj->addrfamily = ai_list->ai_family;

			freeaddrinfo (ai_list);
		} /* case PING_OPT_SOURCE */
		break;

		case PING_OPT_DEVICE:
		{
#ifdef SO_BINDTODEVICE
			char *device = strdup ((char *) value);

			if (device == NULL)
			{
				ping_set_errno (obj, errno);
				ret = -1;
				break;
			}

			if (obj->device != NULL)
				free (obj->device);
			obj->device = device;
#else /* ! SO_BINDTODEVICE */
			ping_set_errno (obj, ENOTSUP);
			ret = -1;
#endif /* ! SO_BINDTODEVICE */
		} /* case PING_OPT_DEVICE */
		break;

		case PING_OPT_MARK:
		{
#ifdef SO_MARK
			obj->mark     = *(int*)(value);
			obj->set_mark = 1;
#else /* SO_MARK */
			ping_set_errno (obj, ENOTSUP);
			ret = -1;
#endif /* !SO_MARK */

		} /* case PING_OPT_MARK */
		break;

		default:
			ret = -2;
	} /* switch (option) */

	return (ret);
} /* int ping_setopt */

int ping_send (pingobj_t *obj)
{
	pinghost_t *ptr;

	struct timeval endtime;
	struct timeval nowtime;
	struct timeval timeout;

	_Bool need_ipv4_socket = 0;
	_Bool need_ipv6_socket = 0;

	for (ptr = obj->head; ptr != NULL; ptr = ptr->next)
	{
		ptr->latency  = -1.0;
		ptr->recv_ttl = -1;

		if (ptr->addrfamily == AF_INET)
			need_ipv4_socket = 1;
		else if (ptr->addrfamily == AF_INET6)
			need_ipv6_socket = 1;
	}

	if (!need_ipv4_socket && !need_ipv6_socket)
	{
		ping_set_error (obj, "ping_send", "No hosts to ping");
		return (-1);
	}

	if (need_ipv4_socket && obj->fd4 == -1)
	{
		obj->fd4 = ping_open_socket(obj, AF_INET);
		if (obj->fd4 == -1)
			return (-1);
		ping_set_ttl (obj, obj->ttl);
		ping_set_qos (obj, obj->qos);
	}
	if (need_ipv6_socket && obj->fd6 == -1)
	{
		obj->fd6 = ping_open_socket(obj, AF_INET6);
		if (obj->fd6 == -1)
			return (-1);
		ping_set_ttl (obj, obj->ttl);
		ping_set_qos (obj, obj->qos);
	}

	if (gettimeofday (&nowtime, NULL) == -1)
	{
		ping_set_errno (obj, errno);
		return (-1);
	}

	/* Set up timeout */
	timeout.tv_sec = (time_t) obj->timeout;
	timeout.tv_usec = (suseconds_t) (1000000 * (obj->timeout - ((double) timeout.tv_sec)));

	dprintf ("Set timeout to %i.%06i seconds\n",
			(int) timeout.tv_sec,
			(int) timeout.tv_usec);

	ping_timeval_add (&nowtime, &timeout, &endtime);

	/* host_to_ping points to the host to which to send the next ping. The
	 * pointer is advanced to the next host in the linked list after the
	 * ping has been sent. If host_to_ping is NULL, no more pings need to be
	 * send out. */
	pinghost_t *host_to_ping = obj->head;

	/* pings_in_flight is the number of hosts we sent a "ping" to but didn't
	 * receive a "pong" yet. */
	int pings_in_flight = 0;

	/* pongs_received is the number of echo replies received. Unless there
	 * is an error, this is used as the return value of ping_send(). */
	int pongs_received = 0;

	int error_count = 0;

	while (pings_in_flight > 0 || host_to_ping != NULL)
	{
		fd_set read_fds;
		fd_set write_fds;

		int write_fd = -1;
		int max_fd = -1;

		FD_ZERO (&read_fds);
		FD_ZERO (&write_fds);

		if (obj->fd4 != -1)
		{
			FD_SET(obj->fd4, &read_fds);
			if (host_to_ping != NULL && host_to_ping->addrfamily == AF_INET)
				write_fd = obj->fd4;

			if (max_fd < obj->fd4)
				max_fd = obj->fd4;
		}

		if (obj->fd6 != -1)
		{
			FD_SET(obj->fd6, &read_fds);
			if (host_to_ping != NULL && host_to_ping->addrfamily == AF_INET6)
				write_fd = obj->fd6;

			if (max_fd < obj->fd6)
				max_fd = obj->fd6;
		}

		if (write_fd != -1)
			FD_SET(write_fd, &write_fds);

		assert (max_fd != -1);
		assert (max_fd < FD_SETSIZE);

		if (gettimeofday (&nowtime, NULL) == -1)
		{
			ping_set_errno (obj, errno);
			return (-1);
		}

		if (ping_timeval_sub (&endtime, &nowtime, &timeout) == -1)
			break;

		dprintf ("Waiting on %i sockets for %u.%06u seconds\n",
				((obj->fd4 != -1) ? 1 : 0) + ((obj->fd6 != -1) ? 1 : 0),
				(unsigned) timeout.tv_sec,
				(unsigned) timeout.tv_usec);

		int status = select (max_fd + 1, &read_fds, &write_fds, NULL, &timeout);

		if (gettimeofday (&nowtime, NULL) == -1)
		{
			ping_set_errno (obj, errno);
			return (-1);
		}

		if (status == -1)
		{
			ping_set_errno (obj, errno);
			dprintf ("select: %s\n", obj->errmsg);
			return (-1);
		}
		else if (status == 0)
		{
			dprintf ("select timed out\n");

			pinghost_t *ph;
			for (ph = obj->head; ph != NULL; ph = ph->next)
				if (ph->latency < 0.0)
					ph->dropped++;
			break;
		}

		/* first, check if we can receive a reply ... */
		if (obj->fd6  != -1 && FD_ISSET (obj->fd6, &read_fds))
		{
			if (ping_receive_one (obj, &nowtime, AF_INET6) == 0)
			{
				pings_in_flight--;
				pongs_received++;
			}
			continue;
		}
		if (obj->fd4 != -1 && FD_ISSET (obj->fd4, &read_fds))
		{
			if (ping_receive_one (obj, &nowtime, AF_INET) == 0)
			{
				pings_in_flight--;
				pongs_received++;
			}
			continue;
		}

		/* ... and if no reply is available to read, continue sending
		 * out pings. */

		/* this condition should always be true. We keep it for
		 * consistency with the read blocks above and just to be on the
		 * safe side. */
		if (write_fd != -1 && FD_ISSET (write_fd, &write_fds))
		{
			if (ping_send_one (obj, host_to_ping, write_fd) == 0)
				pings_in_flight++;
			else
				error_count++;
			host_to_ping = host_to_ping->next;
			continue;
		}
	} /* while (1) */

	if (error_count)
		return (-1 * error_count);
	return (pongs_received);
} /* int ping_send */

static pinghost_t *ping_host_search (pinghost_t *ph, const char *host)
{
	while (ph != NULL)
	{
		if (strcasecmp (ph->username, host) == 0)
			break;

		ph = ph->next;
	}

	return (ph);
}

int ping_host_add (pingobj_t *obj, const char *host)
{
	pinghost_t *ph;

	struct addrinfo  ai_hints;
	struct addrinfo *ai_list, *ai_ptr;
	int              ai_return;

	if ((obj == NULL) || (host == NULL))
		return (-1);

	dprintf ("host = %s\n", host);

	if (ping_host_search (obj->head, host) != NULL)
		return (0);

	memset (&ai_hints, '\0', sizeof (ai_hints));
	ai_hints.ai_flags     = 0;
#ifdef AI_ADDRCONFIG
	ai_hints.ai_flags    |= AI_ADDRCONFIG;
#endif
#ifdef AI_CANONNAME
	ai_hints.ai_flags    |= AI_CANONNAME;
#endif
	ai_hints.ai_family    = obj->addrfamily;
	ai_hints.ai_socktype  = SOCK_RAW;

	if ((ph = ping_alloc ()) == NULL)
	{
		dprintf ("Out of memory!\n");
		return (-1);
	}

	if ((ph->username = strdup (host)) == NULL)
	{
		dprintf ("Out of memory!\n");
		ping_set_errno (obj, errno);
		ping_free (ph);
		return (-1);
	}

	if ((ph->hostname = strdup (host)) == NULL)
	{
		dprintf ("Out of memory!\n");
		ping_set_errno (obj, errno);
		ping_free (ph);
		return (-1);
	}

	/* obj->data is not garuanteed to be != NULL */
	if ((ph->data = strdup (obj->data == NULL ? PING_DEF_DATA : obj->data)) == NULL)
	{
		dprintf ("Out of memory!\n");
		ping_set_errno (obj, errno);
		ping_free (ph);
		return (-1);
	}

	if ((ai_return = getaddrinfo (host, NULL, &ai_hints, &ai_list)) != 0)
	{
#if defined(EAI_SYSTEM)
		char errbuf[PING_ERRMSG_LEN];
#endif
		dprintf ("getaddrinfo failed\n");
		ping_set_error (obj, "getaddrinfo",
#if defined(EAI_SYSTEM)
						(ai_return == EAI_SYSTEM)
						? sstrerror (errno, errbuf, sizeof (errbuf)) :
#endif
				gai_strerror (ai_return));
		ping_free (ph);
		return (-1);
	}

	if (ai_list == NULL)
		ping_set_error (obj, "getaddrinfo", "No hosts returned");

	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next)
	{
		if (ai_ptr->ai_family == AF_INET)
		{
			ai_ptr->ai_socktype = SOCK_RAW;
			ai_ptr->ai_protocol = IPPROTO_ICMP;
		}
		else if (ai_ptr->ai_family == AF_INET6)
		{
			ai_ptr->ai_socktype = SOCK_RAW;
			ai_ptr->ai_protocol = IPPROTO_ICMPV6;
		}
		else
		{
			char errmsg[PING_ERRMSG_LEN];

			snprintf (errmsg, PING_ERRMSG_LEN, "Unknown `ai_family': %i", ai_ptr->ai_family);
			errmsg[PING_ERRMSG_LEN - 1] = '\0';

			dprintf ("%s", errmsg);
			ping_set_error (obj, "getaddrinfo", errmsg);
			continue;
		}

		assert (sizeof (struct sockaddr_storage) >= ai_ptr->ai_addrlen);
		memset (ph->addr, '\0', sizeof (struct sockaddr_storage));
		memcpy (ph->addr, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
		ph->addrlen = ai_ptr->ai_addrlen;
		ph->addrfamily = ai_ptr->ai_family;

#ifdef AI_CANONNAME
		if ((ai_ptr->ai_canonname != NULL)
				&& (strcmp (ph->hostname, ai_ptr->ai_canonname) != 0))
		{
			char *old_hostname;

			dprintf ("ph->hostname = %s; ai_ptr->ai_canonname = %s;\n",
					ph->hostname, ai_ptr->ai_canonname);

			old_hostname = ph->hostname;
			if ((ph->hostname = strdup (ai_ptr->ai_canonname)) == NULL)
			{
				/* strdup failed, falling back to old hostname */
				ph->hostname = old_hostname;
			}
			else if (old_hostname != NULL)
			{
				free (old_hostname);
			}
		}
#endif /* AI_CANONNAME */
	} /* for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) */

	freeaddrinfo (ai_list);

	/*
	 * Adding in the front is much easier, but then the iterator will
	 * return the host that was added last as first host. That's just not
	 * nice. -octo
	 */
	if (obj->head == NULL)
	{
		obj->head = ph;
	}
	else
	{
		pinghost_t *hptr;

		hptr = obj->head;
		while (hptr->next != NULL)
			hptr = hptr->next;

		assert ((hptr != NULL) && (hptr->next == NULL));
		hptr->next = ph;
	}

	ph->table_next = obj->table[ph->ident % PING_TABLE_LEN];
	obj->table[ph->ident % PING_TABLE_LEN] = ph;

	return (0);
} /* int ping_host_add */

int ping_host_remove (pingobj_t *obj, const char *host)
{
	pinghost_t *pre, *cur, *target;

	if ((obj == NULL) || (host == NULL))
		return (-1);

	pre = NULL;
	cur = obj->head;

	while (cur != NULL)
	{
		if (strcasecmp (host, cur->username) == 0)
			break;

		pre = cur;
		cur = cur->next;
	}

	if (cur == NULL)
	{
		ping_set_error (obj, "ping_host_remove", "Host not found");
		return (-1);
	}

	if (pre == NULL)
		obj->head = cur->next;
	else
		pre->next = cur->next;

	target = cur;
	pre = NULL;

	cur = obj->table[target->ident % PING_TABLE_LEN];

	while (cur != NULL)
	{
		if (cur == target)
			break;

		pre = cur;
		cur = cur->table_next;
	}

	if (cur == NULL)
	{
		ping_set_error(obj, "ping_host_remove", "Host not found (T)");
		ping_free(target);
		return (-1);
	}

	if (pre == NULL)
		obj->table[target->ident % PING_TABLE_LEN] = cur->table_next;
	else
		pre->table_next = cur->table_next;

	ping_free (cur);

	return (0);
}

pingobj_iter_t *ping_iterator_get (pingobj_t *obj)
{
	if (obj == NULL)
		return (NULL);
	return ((pingobj_iter_t *) obj->head);
}

pingobj_iter_t *ping_iterator_next (pingobj_iter_t *iter)
{
	if (iter == NULL)
		return (NULL);
	return ((pingobj_iter_t *) iter->next);
}

int ping_iterator_count (pingobj_t *obj)
{
	if (obj == NULL)
		return 0;

	int count = 0;
	pingobj_iter_t *iter = obj->head;
	while (iter) {
		count++;
		iter = iter->next;
	}
	return count;
}

int ping_iterator_get_info (pingobj_iter_t *iter, int info,
		void *buffer, size_t *buffer_len)
{
	int ret = EINVAL;

	size_t orig_buffer_len = *buffer_len;

	if ((iter == NULL) || (buffer_len == NULL))
		return (-1);

	if ((buffer == NULL) && (*buffer_len != 0 ))
		return (-1);

	switch (info)
	{
		case PING_INFO_USERNAME:
			ret = ENOMEM;
			*buffer_len = strlen (iter->username) + 1;
			if (orig_buffer_len <= *buffer_len)
				break;
			/* Since (orig_buffer_len > *buffer_len) `strncpy'
			 * will copy `*buffer_len' and pad the rest of
			 * `buffer' with null-bytes */
			strncpy (buffer, iter->username, orig_buffer_len);
			ret = 0;
			break;

		case PING_INFO_HOSTNAME:
			ret = ENOMEM;
			*buffer_len = strlen (iter->hostname) + 1;
			if (orig_buffer_len < *buffer_len)
				break;
			/* Since (orig_buffer_len > *buffer_len) `strncpy'
			 * will copy `*buffer_len' and pad the rest of
			 * `buffer' with null-bytes */
			strncpy (buffer, iter->hostname, orig_buffer_len);
			ret = 0;
			break;

		case PING_INFO_ADDRESS:
			ret = getnameinfo ((struct sockaddr *) iter->addr,
					iter->addrlen,
					(char *) buffer,
					*buffer_len,
					NULL, 0,
					NI_NUMERICHOST);
			if (ret != 0)
			{
				if ((ret == EAI_MEMORY)
#ifdef EAI_OVERFLOW
						|| (ret == EAI_OVERFLOW)
#endif
				   )
					ret = ENOMEM;
#if defined(EAI_SYSTEM)
				else if (ret == EAI_SYSTEM)
					ret = errno;
#endif
				else
					ret = EINVAL;
			}
			break;

		case PING_INFO_FAMILY:
			ret = ENOMEM;
			*buffer_len = sizeof (int);
			if (orig_buffer_len < sizeof (int))
				break;
			*((int *) buffer) = iter->addrfamily;
			ret = 0;
			break;

		case PING_INFO_LATENCY:
			ret = ENOMEM;
			*buffer_len = sizeof (double);
			if (orig_buffer_len < sizeof (double))
				break;
			*((double *) buffer) = iter->latency;
			ret = 0;
			break;

		case PING_INFO_DROPPED:
			ret = ENOMEM;
			*buffer_len = sizeof (uint32_t);
			if (orig_buffer_len < sizeof (uint32_t))
				break;
			*((uint32_t *) buffer) = iter->dropped;
			ret = 0;
			break;

		case PING_INFO_SEQUENCE:
			ret = ENOMEM;
			*buffer_len = sizeof (unsigned int);
			if (orig_buffer_len < sizeof (unsigned int))
				break;
			*((unsigned int *) buffer) = (unsigned int) iter->sequence;
			ret = 0;
			break;

		case PING_INFO_IDENT:
			ret = ENOMEM;
			*buffer_len = sizeof (uint16_t);
			if (orig_buffer_len < sizeof (uint16_t))
				break;
			*((uint16_t *) buffer) = (uint16_t) iter->ident;
			ret = 0;
			break;

		case PING_INFO_DATA:
			ret = ENOMEM;
			*buffer_len = strlen (iter->data);
			if (orig_buffer_len < *buffer_len)
				break;
			strncpy ((char *) buffer, iter->data, orig_buffer_len);
			ret = 0;
			break;

		case PING_INFO_RECV_TTL:
			ret = ENOMEM;
			*buffer_len = sizeof (int);
			if (orig_buffer_len < sizeof (int))
				break;
			*((int *) buffer) = iter->recv_ttl;
			ret = 0;
			break;

		case PING_INFO_RECV_QOS:
			ret = ENOMEM;
			if (*buffer_len>sizeof(unsigned)) *buffer_len=sizeof(unsigned);
			if (!*buffer_len) *buffer_len=1;
			if (orig_buffer_len < *buffer_len)
				break;
			memcpy(buffer,&iter->recv_qos,*buffer_len);
			ret = 0;
			break;
	}

	return (ret);
} /* ping_iterator_get_info */

void *ping_iterator_get_context (pingobj_iter_t *iter)
{
	if (iter == NULL)
		return (NULL);
	return (iter->context);
}

void ping_iterator_set_context (pingobj_iter_t *iter, void *context)
{
	if (iter == NULL)
		return;
	iter->context = context;
}
