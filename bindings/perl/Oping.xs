#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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
_ping_setopt_source (obj, addr)
	pingobj_t *obj
	char *addr
	CODE:
		RETVAL = ping_setopt (obj, PING_OPT_SOURCE, addr);
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

		/* FIXME: This is a workaround for a bug in 0.3.5. */
		buffer_size++;

		buffer = (char *) malloc (buffer_size);
		if (buffer == NULL)
			break;

		status = ping_iterator_get_info (iter, PING_INFO_HOSTNAME,
				(void *) buffer, &buffer_size);
		if (status != 0)
			break;

		XPUSHs (sv_2mortal (newSVpvn(buffer,buffer_size)));
		free(buffer);
	} while (0);

const char *
_ping_get_error (obj)
	pingobj_t *obj
	CODE:
		RETVAL = ping_get_error(obj);
	OUTPUT:
		RETVAL
