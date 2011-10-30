/**
 * Object oriented C module to send ICMP and ICMPv6 `echo's.
 * Copyright (C) 2006-2011  Florian octo Forster <ff at octo.it>
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

struct pinghost
{
	/* username: name passed in by the user */
	char                    *username;
	/* hostname: name returned by the reverse lookup */
	char                    *hostname;
	struct sockaddr_storage *addr;
	socklen_t                addrlen;
	int                      addrfamily;
	int                      fd;
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
};

struct pingobj
{
	double                   timeout;
	int                      ttl;
	int                      addrfamily;
	uint8_t                  qos;
	char                    *data;

	struct sockaddr         *srcaddr;
	socklen_t                srcaddrlen;

	char                    *device;

	char                     errmsg[PING_ERRMSG_LEN];

	pinghost_t              *head;
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

	if (buffer_len < sizeof (struct icmp))
		return (NULL);

	icmp_hdr = (struct icmp *) buffer;
	buffer     += sizeof (struct icmp);
	buffer_len -= sizeof (struct icmp);

	if (icmp_hdr->icmp_type != ICMP_ECHOREPLY)
	{
		dprintf ("Unexpected ICMP type: %i\n", icmp_hdr->icmp_type);
		return (NULL);
	}

	recv_checksum = icmp_hdr->icmp_cksum;
	icmp_hdr->icmp_cksum = 0;
	calc_checksum = ping_icmp4_checksum ((char *) icmp_hdr,
			sizeof (struct icmp) + buffer_len);

	if (recv_checksum != calc_checksum)
	{
		dprintf ("Checksum missmatch: Got 0x%04"PRIx16", "
				"calculated 0x%04"PRIx16"\n",
				recv_checksum, calc_checksum);
		return (NULL);
	}

	ident = ntohs (icmp_hdr->icmp_id);
	seq   = ntohs (icmp_hdr->icmp_seq);

	/* We have to iterate over all hosts, since ICMPv4 packets may
	 * be received on any raw v4 socket. */
	for (ptr = obj->head; ptr != NULL; ptr = ptr->next)
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

	if (buffer_len < sizeof (struct icmp6_hdr))
		return (NULL);

	icmp_hdr = (struct icmp6_hdr *) buffer;
	buffer     += sizeof (struct icmp);
	buffer_len -= sizeof (struct icmp);

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

static int ping_receive_one (pingobj_t *obj, const pinghost_t *ph,
		struct timeval *now)
{
	/* Note: 'ph' is not necessarily the host object for which we receive a
	 * reply. The right object will be returned by ping_receive_ipv*(). For
	 * now, we can only rely on ph->fd and ph->addrfamily. */

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

	payload_buffer_len = recvmsg (ph->fd, &msghdr, /* flags = */ 0);
	if (payload_buffer_len < 0)
	{
#if WITH_DEBUG
		char errbuf[PING_ERRMSG_LEN];
		dprintf ("recvfrom: %s\n",
				sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
		return (-1);
	}
	dprintf ("Read %zi bytes from fd = %i\n", payload_buffer_len, ph->fd);

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
		else if (ph->addrfamily == AF_INET) /* {{{ */
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
		else if (ph->addrfamily == AF_INET6) /* {{{ */
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

	if (ph->addrfamily == AF_INET)
	{
		host = ping_receive_ipv4 (obj, payload_buffer, payload_buffer_len);
		if (host == NULL)
			return (-1);
	}
	else if (ph->addrfamily == AF_INET6)
	{
		host = ping_receive_ipv6 (obj, payload_buffer, payload_buffer_len);
		if (host == NULL)
			return (-1);
	}
	else
	{
		dprintf ("ping_receive_one: Unknown address family %i.\n",
				ph->addrfamily);
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

static int ping_receive_all (pingobj_t *obj)
{
	fd_set read_fds;
	fd_set err_fds;
	int num_fds;
	int max_fd;

	pinghost_t *ph;
	pinghost_t *ptr;

	struct timeval endtime;
	struct timeval nowtime;
	struct timeval timeout;
	int status;

	int ret;

	ph = obj->head;
	ret = 0;

	for (ptr = ph; ptr != NULL; ptr = ptr->next)
	{
		ptr->latency  = -1.0;
		ptr->recv_ttl = -1;
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

	while (1)
	{
		FD_ZERO (&read_fds);
		FD_ZERO (&err_fds);
		num_fds =  0;
		max_fd = -1;

		for (ptr = ph; ptr != NULL; ptr = ptr->next)
		{
			if (!timerisset (ptr->timer))
				continue;

			FD_SET (ptr->fd, &read_fds);
			FD_SET (ptr->fd, &err_fds);
			num_fds++;

			if (max_fd < ptr->fd)
				max_fd = ptr->fd;
		}

		if (num_fds == 0)
			break;

		if (gettimeofday (&nowtime, NULL) == -1)
		{
			ping_set_errno (obj, errno);
			return (-1);
		}

		if (ping_timeval_sub (&endtime, &nowtime, &timeout) == -1)
			break;

		dprintf ("Waiting on %i sockets for %i.%06i seconds\n", num_fds,
				(int) timeout.tv_sec,
				(int) timeout.tv_usec);

		status = select (max_fd + 1, &read_fds, NULL, &err_fds, &timeout);

		if (gettimeofday (&nowtime, NULL) == -1)
		{
			ping_set_errno (obj, errno);
			return (-1);
		}
		
		if ((status == -1) && (errno == EINTR))
		{
			dprintf ("select was interrupted by signal..\n");
			continue;
		}
		else if (status < 0)
		{
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("select: %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			break;
		}
		else if (status == 0)
		{
			dprintf ("select timed out\n");
			for (ptr = ph; ptr != NULL; ptr = ptr->next)
				if (ptr->latency < 0.0)
					ptr->dropped++;
			break;
		}

		for (ptr = ph; ptr != NULL; ptr = ptr->next)
		{
			if (FD_ISSET (ptr->fd, &read_fds))
			{
				if (ping_receive_one (obj, ptr, &nowtime) == 0)
					ret++;
			}
			else if (FD_ISSET (ptr->fd, &err_fds))
			{
				/* clear the timer in this case so that we
				 * don't run into an endless loop. */
				/* TODO: Set an error flag in this case. */
				timerclear (ptr->timer);
			}
		}
	} /* while (1) */
	
	return (ret);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Sending functions:                                                        *
 *                                                                           *
 * ping_send_all                                                             *
 * +-> ping_send_one_ipv4                                                    *
 * `-> ping_send_one_ipv6                                                    *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
static ssize_t ping_sendto (pingobj_t *obj, pinghost_t *ph,
		const void *buf, size_t buflen)
{
	ssize_t ret;

	if (gettimeofday (ph->timer, NULL) == -1)
	{
		timerclear (ph->timer);
		return (-1);
	}

	ret = sendto (ph->fd, buf, buflen, 0,
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

static int ping_send_one_ipv4 (pingobj_t *obj, pinghost_t *ph)
{
	struct icmp *icmp4;
	int status;

	char buf[4096];
	int  buflen;

	char *data;
	int   datalen;

	dprintf ("ph->hostname = %s\n", ph->hostname);

	memset (buf, '\0', sizeof (buf));
	icmp4 = (struct icmp *) buf;
	data  = (char *) (icmp4 + 1);

	icmp4->icmp_type  = ICMP_ECHO;
	icmp4->icmp_code  = 0;
	icmp4->icmp_cksum = 0;
	icmp4->icmp_id    = htons (ph->ident);
	icmp4->icmp_seq   = htons (ph->sequence);

	buflen = 4096 - sizeof (struct icmp);
	strncpy (data, ph->data, buflen);
	datalen = strlen (data);

	buflen = datalen + sizeof (struct icmp);

	icmp4->icmp_cksum = ping_icmp4_checksum (buf, buflen);

	dprintf ("Sending ICMPv4 package with ID 0x%04x\n", ph->ident);

	status = ping_sendto (obj, ph, buf, buflen);
	if (status < 0)
	{
		perror ("ping_sendto");
		return (-1);
	}

	dprintf ("sendto: status = %i\n", status);

	return (0);
}

static int ping_send_one_ipv6 (pingobj_t *obj, pinghost_t *ph)
{
	struct icmp6_hdr *icmp6;
	int status;

	char buf[4096];
	int  buflen;

	char *data;
	int   datalen;

	dprintf ("ph->hostname = %s\n", ph->hostname);

	memset (buf, '\0', sizeof (buf));
	icmp6 = (struct icmp6_hdr *) buf;
	data  = (char *) (icmp6 + 1);

	icmp6->icmp6_type  = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code  = 0;
	/* The checksum will be calculated by the TCP/IP stack.  */
	/* FIXME */
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_id    = htons (ph->ident);
	icmp6->icmp6_seq   = htons (ph->sequence);

	buflen = 4096 - sizeof (struct icmp6_hdr);
	strncpy (data, ph->data, buflen);
	datalen = strlen (data);

	buflen = datalen + sizeof (struct icmp6_hdr);

	dprintf ("Sending ICMPv6 package with ID 0x%04x\n", ph->ident);

	status = ping_sendto (obj, ph, buf, buflen);
	if (status < 0)
	{
		perror ("ping_sendto");
		return (-1);
	}

	dprintf ("sendto: status = %i\n", status);

	return (0);
}

static int ping_send_all (pingobj_t *obj)
{
	pinghost_t *ph;
	pinghost_t *ptr;

	int ret;

	ret = 0;
	ph = obj->head;

	for (ptr = ph; ptr != NULL; ptr = ptr->next)
	{
		/* start timer.. The GNU `ping6' starts the timer before
		 * sending the packet, so I will do that too */
		if (gettimeofday (ptr->timer, NULL) == -1)
		{
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("gettimeofday: %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			timerclear (ptr->timer);
			ret--;
			continue;
		}
		else
		{
			dprintf ("timer set for hostname = %s\n", ptr->hostname);
		}

		if (ptr->addrfamily == AF_INET6)
		{	
			dprintf ("Sending ICMPv6 echo request to `%s'\n", ptr->hostname);
			if (ping_send_one_ipv6 (obj, ptr) != 0)
			{
				timerclear (ptr->timer);
				ret--;
				continue;
			}
		}
		else if (ptr->addrfamily == AF_INET)
		{
			dprintf ("Sending ICMPv4 echo request to `%s'\n", ptr->hostname);
			if (ping_send_one_ipv4 (obj, ptr) != 0)
			{
				timerclear (ptr->timer);
				ret--;
				continue;
			}
		}
		else /* this should not happen */
		{
			dprintf ("Unknown address family: %i\n", ptr->addrfamily);
			timerclear (ptr->timer);
			ret--;
			continue;
		}

		ptr->sequence++;
	}

	return (ret);
}

/*
 * Set the TTL of a socket protocol independently.
 */
static int ping_set_ttl (pinghost_t *ph, int ttl)
{
	int ret = -2;

	if (ph->addrfamily == AF_INET)
	{
		dprintf ("Setting TTLv4 to %i\n", ttl);
		ret = setsockopt (ph->fd, IPPROTO_IP, IP_TTL,
				&ttl, sizeof (ttl));
	}
	else if (ph->addrfamily == AF_INET6)
	{
		dprintf ("Setting TTLv6 to %i\n", ttl);
		ret = setsockopt (ph->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&ttl, sizeof (ttl));
	}

	return (ret);
}

/*
 * Set the TOS of a socket protocol independently.
 *
 * Using SOL_SOCKET / SO_PRIORITY might be a protocol independent way to
 * set this. See socket(7) for details.
 */
static int ping_set_qos (pingobj_t *obj, pinghost_t *ph, uint8_t qos)
{
	int ret = EINVAL;
	char errbuf[PING_ERRMSG_LEN];

	if (ph->addrfamily == AF_INET)
	{
		dprintf ("Setting TP_TOS to %#04"PRIx8"\n", qos);
		ret = setsockopt (ph->fd, IPPROTO_IP, IP_TOS,
				&qos, sizeof (qos));
		if (ret != 0)
		{
			ret = errno;
			ping_set_error (obj, "ping_set_qos",
					sstrerror (ret, errbuf, sizeof (errbuf)));
			dprintf ("Setting TP_TOS failed: %s\n", errbuf);
		}
	}
	else if (ph->addrfamily == AF_INET6)
	{
		/* IPV6_TCLASS requires an "int". */
		int tmp = (int) qos;

		dprintf ("Setting IPV6_TCLASS to %#04"PRIx8" (%i)\n", qos, tmp);
		ret = setsockopt (ph->fd, IPPROTO_IPV6, IPV6_TCLASS,
				&tmp, sizeof (tmp));
		if (ret != 0)
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
	ph->fd      = -1;
	ph->latency = -1.0;
	ph->dropped = 0;
	ph->ident   = ping_get_ident () & 0xFFFF;

	return (ph);
}

static void ping_free (pinghost_t *ph)
{
	if (ph->fd >= 0)
		close (ph->fd);
	
	if (ph->username != NULL)
		free (ph->username);

	if (ph->hostname != NULL)
		free (ph->hostname);

	if (ph->data != NULL)
		free (ph->data);

	free (ph);
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

	if ((obj = (pingobj_t *) malloc (sizeof (pingobj_t))) == NULL)
		return (NULL);
	memset (obj, 0, sizeof (pingobj_t));

	obj->timeout    = PING_DEF_TIMEOUT;
	obj->ttl        = PING_DEF_TTL;
	obj->addrfamily = PING_DEF_AF;
	obj->data       = strdup (PING_DEF_DATA);
	obj->qos        = 0;

	return (obj);
}

void ping_destroy (pingobj_t *obj)
{
	pinghost_t *current;
	pinghost_t *next;

	if (obj == NULL)
		return;

	current = obj->head;
	next = NULL;

	while (current != NULL)
	{
		next = current->next;
		ping_free (current);
		current = next;
	}

	if (obj->data != NULL)
		free (obj->data);

	if (obj->srcaddr != NULL)
		free (obj->srcaddr);

	if (obj->device != NULL)
		free (obj->device);

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
			pinghost_t *ph;

			obj->qos = *((uint8_t *) value);
			for (ph = obj->head; ph != NULL; ph = ph->next)
				ping_set_qos (obj, ph, obj->qos);
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
			obj->ttl = *((int *) value);
			if ((obj->ttl < 1) || (obj->ttl > 255))
			{
				obj->ttl = PING_DEF_TTL;
				ret = -1;
			}
			else
			{
				pinghost_t *ph;

				for (ph = obj->head; ph != NULL; ph = ph->next)
					ping_set_ttl (ph, obj->ttl);
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

		default:
			ret = -2;
	} /* switch (option) */

	return (ret);
} /* int ping_setopt */


int ping_send (pingobj_t *obj)
{
	int ret;

	if (obj == NULL)
		return (-1);

	if (ping_send_all (obj) < 0)
		return (-1);

	if ((ret = ping_receive_all (obj)) < 0)
		return (-2);

	return (ret);
}

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
		ph->fd = -1;

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

		/* TODO: Move this to a static function `ping_open_socket' and
		 * call it whenever the socket dies. */
		ph->fd = socket (ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (ph->fd == -1)
		{
#if WITH_DEBUG
			char errbuf[PING_ERRMSG_LEN];
			dprintf ("socket: %s\n",
					sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
			ping_set_errno (obj, errno);
			continue;
		}

		if (obj->srcaddr != NULL)
		{
			assert (obj->srcaddrlen > 0);
			assert (obj->srcaddrlen <= sizeof (struct sockaddr_storage));

			if (bind (ph->fd, obj->srcaddr, obj->srcaddrlen) == -1)
			{
#if WITH_DEBUG
				char errbuf[PING_ERRMSG_LEN];
				dprintf ("bind: %s\n",
						sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
				ping_set_errno (obj, errno);
				close (ph->fd);
				ph->fd = -1;
				continue;
			}
		}

#ifdef SO_BINDTODEVICE
		if (obj->device != NULL)
		{
			if (setsockopt (ph->fd, SOL_SOCKET, SO_BINDTODEVICE,
					obj->device, strlen (obj->device) + 1) != 0)
			{
#if WITH_DEBUG
				char errbuf[PING_ERRMSG_LEN];
				dprintf ("setsockopt (SO_BINDTODEVICE): %s\n",
						sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
				ping_set_errno (obj, errno);
				close (ph->fd);
				ph->fd = -1;
				continue;
			}
		}
#endif /* SO_BINDTODEVICE */
#ifdef SO_TIMESTAMP
		if (1) /* {{{ */
		{
			int status;
			int opt = 1;

			status = setsockopt (ph->fd,
					SOL_SOCKET, SO_TIMESTAMP,
					&opt, sizeof (opt));
			if (status != 0)
			{
#if WITH_DEBUG
				char errbuf[PING_ERRMSG_LEN];
				dprintf ("setsockopt (SO_TIMESTAMP): %s\n",
						sstrerror (errno, errbuf, sizeof (errbuf)));
#endif
				ping_set_errno (obj, errno);
				close (ph->fd);
				ph->fd = -1;
				continue;
			}
		} /* }}} if (1) */
#endif /* SO_TIMESTAMP */
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

		if (ph->addrfamily == AF_INET)
		{
			int opt;

#ifdef IP_RECVTOS
			/* Enable receiving the TOS field */
			opt = 1;
			setsockopt (ph->fd, IPPROTO_IP, IP_RECVTOS,
					&opt, sizeof (opt));
#endif	/* IP_RECVTOS */

			/* Enable receiving the TTL field */
			opt = 1;
			setsockopt (ph->fd, IPPROTO_IP, IP_RECVTTL,
					&opt, sizeof (opt));
		}
#if defined(IPV6_RECVHOPLIMIT) || defined(IPV6_RECVTCLASS)
		else if (ph->addrfamily == AF_INET6)
		{
			int opt;

# if defined(IPV6_RECVHOPLIMIT)
			/* For details see RFC 3542, section 6.3. */
			opt = 1;
			setsockopt (ph->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
					&opt, sizeof (opt));
# endif /* IPV6_RECVHOPLIMIT */

# if defined(IPV6_RECVTCLASS)
			/* For details see RFC 3542, section 6.5. */
			opt = 1;
			setsockopt (ph->fd, IPPROTO_IPV6, IPV6_RECVTCLASS,
					&opt, sizeof (opt));
# endif /* IPV6_RECVTCLASS */
		}
#endif /* IPV6_RECVHOPLIMIT || IPV6_RECVTCLASS */

		break;
	} /* for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) */

	freeaddrinfo (ai_list);

	if (ph->fd < 0)
	{
		ping_free (ph);
		return (-1);
	}

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

	ping_set_ttl (ph, obj->ttl);
	ping_set_qos (obj, ph, obj->qos);

	return (0);
} /* int ping_host_add */

int ping_host_remove (pingobj_t *obj, const char *host)
{
	pinghost_t *pre, *cur;

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
