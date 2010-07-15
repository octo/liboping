/**
 * Object oriented C module to send ICMP and ICMPv6 `echo's.
 * Copyright (C) 2006-2010  Florian octo Forster
 * Copyright (C) 2010       Julien Ammous
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
 *
 * Authors:
 *   Florian octo Forster <octo at verplant.org>
 *   Julien Ammous <j.ammous at gmail.com>
 */

#ifndef OPING_PRIVATE_H
#define OPING_PRIVATE_H 1

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef IP_ALEN
#define IP_ALEN 4
#endif

#define PING_ERRMSG_LEN 256

#if WITH_DEBUG
# define dprintf(...) printf ("%s[%4i]: %-20s: ", __FILE__, __LINE__, __FUNCTION__); printf (__VA_ARGS__)
#else
# define dprintf(...) /**/
#endif

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_LIBNET_H
#include <libnet.h>
#endif


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
	char                    *data;
#ifdef ENABLE_ARP
  int                      timeout_reached;
#endif

	void                    *context;

	struct pinghost         *next;
};

struct pingobj
{
	double                   timeout;
	int                      ttl;
	int                      addrfamily;
	char                    *data;

	struct sockaddr         *srcaddr;
	socklen_t                srcaddrlen;

	char                    *device;

	char                     errmsg[PING_ERRMSG_LEN];

	pinghost_t              *head;

#ifdef ENABLE_ARP
	/* arp */
	int                     use_arp;
	pcap_t                  *pcap;
	libnet_t                *ln;
	uint8_t                 srcmac[ETH_ALEN];
#endif
};

#ifdef ENABLE_ARP
int arp_init(pingobj_t *pingobj);
void ping_destroy_arp (pingobj_t *obj);
int ping_send_all_arp(pingobj_t *obj);
int ping_receive_all_arp(pingobj_t *obj);
#else
# define ping_destroy_arp(obj) /**/
#endif

#endif /* OPING_PRIVATE_H */
