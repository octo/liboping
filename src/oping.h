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

#ifndef OCTO_PING_H
#define OCTO_PING_H 1

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OPING_VERSION 1006002

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
#define PING_OPT_QOS     0x40

#define PING_DEF_TIMEOUT 1.0
#define PING_DEF_TTL     255
#define PING_DEF_AF      AF_UNSPEC
#define PING_DEF_DATA    "liboping -- ICMP ping library <http://octo.it/liboping/>"

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
#define PING_INFO_RECV_QOS 11
int ping_iterator_get_info (pingobj_iter_t *iter, int info,
		void *buffer, size_t *buffer_len);

const char *ping_get_error (pingobj_t *obj);

void *ping_iterator_get_context (pingobj_iter_t *iter);
void  ping_iterator_set_context (pingobj_iter_t *iter, void *context);

/*
 * Asynchronous interface
 */
struct oping_s;
typedef struct oping_s oping_t;

/* Options passed to oping_create() */
struct oping_options_s
{
	/* Number of sequence numbers to keep in memory. This is used to detect
	 * duplicates and effectively defined the timeout. For example, if you
	 * set this to 100 and send two echo request per second, the timeout
	 * effectively becomes 100 * 0.5 = 50 seconds. Values greater than
	 * 65536 (2^16) don't make sense and are capped. Defaults to 256. */
	unsigned int backlog;
};
typedef struct oping_options_s oping_options_t;

/* Per-packet information. This is passed to the callback function to inform
 * about a received echo response. */
struct oping_sample_s
{
	oping_t *obj;
	/* Round-trip time in seconds */
	double   latency;
	/* If true, another response for the same sequence number was
         * previously received. */
	_Bool    duplicate;
	/* Sequence number of this response */
	uint16_t sequence;
	/* Time-to-live of the received IP packet. */
	uint8_t  ttl;
	/* Quality of Service byte of the received IP packet. */
	uint8_t  qos;
};
typedef struct oping_sample_s oping_sample_t;

/* Creates a new oping_t* object. */
oping_t *oping_create (char const *node, /* node / host to ping. */
		oping_options_t const *options, /* NULL for default */
		int (*callback) (oping_sample_t *, void *user_data),
		void *user_data);
/* Destroys a oping_t* object. */
void oping_destroy (oping_t *obj);

/* Increases the sequence number and sends an ICMP echo request to the node. */
int oping_send (oping_t *obj);

/* Query various static information. oping_get_hostname() and
 * oping_get_address() return a pointer to memory inside the oping_t* object.
 * Their reply must not be freed. */
/* If "resolved" is false, return hostname as provided by the user to
 * oping_create(). If true, returns the reverse lookup of the IP address if
 * available and the user provided name if not. */
char const   *oping_get_hostname      (oping_t *obj, _Bool resolved);
char const   *oping_get_address       (oping_t *obj);
int           oping_get_addrfamily    (oping_t *obj);
uint16_t      oping_get_ident         (oping_t *obj);
unsigned long oping_get_sent          (oping_t *obj);
unsigned long oping_get_received      (oping_t *obj);
unsigned long oping_get_duplicates    (oping_t *obj);

/*
 * Potential extentions:
 *
 * Timer, sends requests periodically and keeps the user from programming their
 * own event loop.
 *
 * oping_timer_create(double interval)
 * oping_timer_destroy(timer)
 * oping_timer_add(timer, oping_t*)
 * oping_timer_remove(timer, char const *hostname);
 */

#ifdef __cplusplus
}
#endif

#endif /* OCTO_PING_H */
