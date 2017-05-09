/**
 * Net-Oping - Oping.xs
 * Copyright (C) 2007       Olivier Fredj
 * Copyright (C) 2008,2009  Florian octo Forster
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
 *
 * Authors:
 *   Olivier Fredj <ofredj at proxad.net>
 *   Florian octo Forster <ff at octo.it>
 */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#include <netdb.h> /* NI_MAXHOST */
#include <oping.h>

MODULE = Net::Oping		PACKAGE = Net::Oping		

PROTOTYPES: DISABLE

pingobj_t *
_ping_construct ()
	CODE:
		RETVAL = ping_construct ();
	OUTPUT:
		RETVAL

void 
_ping_destroy (obj);
	pingobj_t *obj
	CODE:
		ping_destroy(obj);

int
_ping_setopt_timeout (obj, timeout)
	pingobj_t *obj
	double timeout
	CODE:
		RETVAL = ping_setopt (obj, PING_OPT_TIMEOUT, &timeout);
	OUTPUT:
		RETVAL

int
_ping_setopt_ttl (obj, ttl)
	pingobj_t *obj
	int ttl
	CODE:
		RETVAL = ping_setopt (obj, PING_OPT_TTL, &ttl);
	OUTPUT:
		RETVAL

int
_ping_setopt_source (obj, addr)
	pingobj_t *obj
	char *addr
	CODE:
		RETVAL = ping_setopt (obj, PING_OPT_SOURCE, addr);
	OUTPUT:
		RETVAL

int
_ping_setopt_device (obj, dev)
	pingobj_t *obj
	char *dev
	CODE:
#if OPING_VERSION >= 1003000
		RETVAL = ping_setopt (obj, PING_OPT_DEVICE, dev);
#else
		RETVAL = -95;
#endif
	OUTPUT:
		RETVAL

int 
_ping_host_add (obj, host);
	pingobj_t *obj
	const char *host
	CODE:
		RETVAL = ping_host_add (obj, host);
	OUTPUT:
		RETVAL

int 
_ping_host_remove (obj, host)
	pingobj_t *obj
	const char *host
	CODE:
		RETVAL = ping_host_remove (obj, host);
	OUTPUT:
		RETVAL

int 
_ping_send (obj)
	pingobj_t *obj
	CODE:
		RETVAL=ping_send (obj);
	OUTPUT:
		RETVAL

pingobj_iter_t *
_ping_iterator_get (obj)
	pingobj_t *obj
	CODE:
		RETVAL = ping_iterator_get (obj);
	OUTPUT:
		RETVAL

pingobj_iter_t *
_ping_iterator_next (iter)
	pingobj_iter_t *iter
	CODE:
		RETVAL = ping_iterator_next (iter);
	OUTPUT:
		RETVAL

int
_ping_iterator_count (obj)
	pingobj_t *obj
	CODE:
		RETVAL = ping_iterator_count (obj);
	OUTPUT:
		RETVAL

double
_ping_iterator_get_latency (iter)
	pingobj_iter_t *iter
	CODE:
		double tmp;
		size_t tmp_size;
		int status;

		RETVAL = -1.0;

		tmp_size = sizeof (tmp);
		status = ping_iterator_get_info (iter, PING_INFO_LATENCY,
			(void *) &tmp, &tmp_size);
		if (status == 0)
			RETVAL = tmp;
	OUTPUT:
		RETVAL

void
_ping_iterator_get_hostname (iter)
	pingobj_iter_t *iter
	PPCODE:
		char *buffer;
		size_t buffer_size;
		int status;

	do {
		buffer = NULL;
		buffer_size = 0;
		status = ping_iterator_get_info (iter, PING_INFO_HOSTNAME,
				(void *) buffer, &buffer_size);
		if (status != ENOMEM)
			break;
#if !defined(OPING_VERSION) || (OPING_VERSION <= 3005)
		/* This is a workaround for a bug in 0.3.5. */
		buffer_size++;
#endif

		buffer = (char *) malloc (buffer_size);
		if (buffer == NULL)
			break;

		status = ping_iterator_get_info (iter, PING_INFO_HOSTNAME,
				(void *) buffer, &buffer_size);
		if (status != 0)
		{
			free (buffer);
			break;
		}
		buffer[buffer_size - 1] = 0;

		XPUSHs (sv_2mortal (newSVpvn(buffer, strlen (buffer))));
		free(buffer);
	} while (0);

int
_ping_iterator_get_dropped (iter)
	pingobj_iter_t *iter
	CODE:
#if defined(PING_INFO_DROPPED)
		uint32_t tmp;
		size_t tmp_size;
		int status;

		RETVAL = -1;

		tmp_size = sizeof (tmp);
		status = ping_iterator_get_info (iter, PING_INFO_DROPPED,
			(void *) &tmp, &tmp_size);
		if (status == 0)
			RETVAL = (int) tmp;
#else
		RETVAL = -1;
#endif
	OUTPUT:
		RETVAL

int
_ping_iterator_get_recv_ttl (iter)
	pingobj_iter_t *iter
	CODE:
#if defined(PING_INFO_RECV_TTL)
		int tmp;
		size_t tmp_size;
		int status;

		RETVAL = -1;

		tmp_size = sizeof (tmp);
		status = ping_iterator_get_info (iter, PING_INFO_RECV_TTL,
			(void *) &tmp, &tmp_size);
		if (status == 0)
			RETVAL = tmp;
#else
		RETVAL = -1;
#endif
	OUTPUT:
		RETVAL

const char *
_ping_get_error (obj)
	pingobj_t *obj
	CODE:
		RETVAL = ping_get_error(obj);
	OUTPUT:
		RETVAL
