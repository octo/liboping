/**
 * Object oriented C module to send ICMP and ICMPv6 `echo's.
 * Copyright (C) 2006-2009  Florian octo Forster <octo at verplant.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; only version 2 of the License is
 * applicable.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef OCTO_PING_H
#define OCTO_PING_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef BUILD_WITH_ARP
#include <pcap.h>
#include <libnet.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define OPING_VERSION 1003003

/*
 * Type definitions
 */
struct pinghost;
typedef struct pinghost pinghost_t;

typedef pinghost_t pingobj_iter_t;

struct pingobj;
typedef struct pingobj pingobj_t;

#define PING_OPT_TIMEOUT 0x01
#define PING_OPT_TTL     0x02
#define PING_OPT_AF      0x04
#define PING_OPT_DATA    0x08
#define PING_OPT_SOURCE  0x10
#define PING_OPT_DEVICE  0x20

#define PING_DEF_TIMEOUT 1.0
#define PING_DEF_TTL     255
#define PING_DEF_AF      AF_UNSPEC
#define PING_DEF_DATA    "Florian Forster <octo@verplant.org> http://verplant.org/"

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
#ifdef BUILD_WITH_ARP
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
	
#ifdef BUILD_WITH_ARP
  // arp
  int                     use_arp;
  pcap_t                  *pcap;
  libnet_t                *ln;
  uint8_t                 srcmac[ETH_ALEN];
#endif
};

/*
 * Method definitions
 */
pingobj_t *ping_construct (void);
void ping_destroy (pingobj_t *obj);

int ping_setopt (pingobj_t *obj, int option, void *value);

int ping_send (pingobj_t *obj);

int ping_host_add (pingobj_t *obj, const char *host);
int ping_host_remove (pingobj_t *obj, const char *host);

pingobj_iter_t *ping_iterator_get (pingobj_t *obj);
pingobj_iter_t *ping_iterator_next (pingobj_iter_t *iter);

#define PING_INFO_HOSTNAME  1
#define PING_INFO_ADDRESS   2
#define PING_INFO_FAMILY    3
#define PING_INFO_LATENCY   4
#define PING_INFO_SEQUENCE  5
#define PING_INFO_IDENT     6
#define PING_INFO_DATA      7
#define PING_INFO_USERNAME  8
#define PING_INFO_DROPPED   9
#define PING_INFO_RECV_TTL 10
int ping_iterator_get_info (pingobj_iter_t *iter, int info,
		void *buffer, size_t *buffer_len);

const char *ping_get_error (pingobj_t *obj);

void *ping_iterator_get_context (pingobj_iter_t *iter);
void  ping_iterator_set_context (pingobj_iter_t *iter, void *context);

#ifdef BUILD_WITH_ARP
int ping_send_all_arp(pingobj_t *obj);
int ping_receive_all_arp(pingobj_t *obj);
int arp_init(pingobj_t *pingobj);
#endif

#ifdef __cplusplus
}
#endif

#endif /* OCTO_PING_H */
