/**
 * Object oriented C module to send ICMP and ICMPv6 `echo's.
 * Copyright (C) 2006  Florian octo Forster <octo at verplant.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if STDC_HEADERS
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <errno.h>
# include <assert.h>
#else
# error "You don't have the standard C99 header files installed"
#endif /* STDC_HEADERS */

#if HAVE_MATH_H
# include <math.h>
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

#if HAVE_NETDB_H
# include <netdb.h> /* NI_MAXHOST */
#endif

#if HAVE_SIGNAL_H
# include <signal.h>
#endif

#include "oping.h"

typedef struct ping_context
{
	char host[NI_MAXHOST];
	char addr[NI_MAXHOST];

	int req_sent;
	int req_rcvd;
	
	double latency_min;
	double latency_max;
	double latency_total;
} ping_context_t;

static double opt_interval   = 1.0;
static int    opt_addrfamily = PING_DEF_AF;
static int    opt_count      = -1;

void sigint_handler (int signal)
{
	/* Exit the loop */
	opt_count = 0;
}

ping_context_t *context_create (void)
{
	ping_context_t *ret;

	if ((ret = malloc (sizeof (ping_context_t))) == NULL)
		return (NULL);

	memset (ret, '\0', sizeof (ping_context_t));

	ret->latency_min   = -1.0;
	ret->latency_max   = -1.0;
	ret->latency_total = 0.0;

	return (ret);
}

void context_destroy (ping_context_t *context)
{
	free (context);
}

void usage_exit (const char *name)
{
	fprintf (stderr, "Usage: %s [-46] [-c count] [-i interval] host [host [host ...]]\n",
			name);
	exit (1);
}

int read_options (int argc, char **argv)
{
	int optchar;

	while (1)
	{
		optchar = getopt (argc, argv, "46c:i:");

		if (optchar == -1)
			break;

		switch (optchar)
		{
			case '4':
			case '6':
				opt_addrfamily = (optchar == '4') ? AF_INET : AF_INET6;
				break;

			case 'c':
				{
					int new_count;
					new_count = atoi (optarg);
					if (new_count > 0)
						opt_count = new_count;
				}
				break;

			case 'i':
				{
					double new_interval;
					new_interval = atof (optarg);
					if (new_interval >= 0.2)
						opt_interval = new_interval;
				}
				break;

			default:
				usage_exit (argv[0]);
		}
	}

	return (optind);
}

void print_host (pingobj_iter_t *iter)
{
	double   latency;
	uint16_t sequence;
	size_t   buffer_len;
	ping_context_t *context;
	
	buffer_len = sizeof (latency);
	ping_iterator_get_info (iter, PING_INFO_LATENCY,
			&latency, &buffer_len);

	buffer_len = sizeof (sequence);
	ping_iterator_get_info (iter, PING_INFO_SEQUENCE,
			&sequence, &buffer_len);

	context = (ping_context_t *) ping_iterator_get_context (iter);

	context->req_sent++;
	if (latency > 0.0)
	{
		context->req_rcvd++;
		context->latency_total += latency;

		if ((context->latency_max < 0.0) || (context->latency_max < latency))
			context->latency_max = latency;
		if ((context->latency_min < 0.0) || (context->latency_min > latency))
			context->latency_min = latency;

		printf ("echo reply from %s (%s): icmp_seq=%u time=%.1f ms\n",
				context->host, context->addr,
				(unsigned int) sequence, latency);
	}
	else
	{
		printf ("echo reply from %s (%s): icmp_seq=%u timeout\n",
				context->host, context->addr,
				(unsigned int) sequence);
	}
}

void time_normalize (struct timespec *ts)
{
	while (ts->tv_nsec < 0)
	{
		if (ts->tv_sec == 0)
		{
			ts->tv_nsec = 0;
			return;
		}

		ts->tv_sec  -= 1;
		ts->tv_nsec += 1000000000;
	}

	while (ts->tv_nsec >= 1000000000)
	{
		ts->tv_sec  += 1;
		ts->tv_nsec -= 1000000000;
	}
}

void time_calc (struct timespec *ts_dest,
		const struct timespec *ts_int,
		const struct timeval  *tv_begin,
		const struct timeval  *tv_end)
{
	ts_dest->tv_sec = tv_begin->tv_sec + ts_int->tv_sec;
	ts_dest->tv_nsec = (tv_begin->tv_usec * 1000) + ts_int->tv_nsec;
	time_normalize (ts_dest);

	/* Assure that `(begin + interval) > end'.
	 * This may seem overly complicated, but `tv_sec' is of type `time_t'
	 * which may be `unsigned. *sigh* */
	if ((tv_end->tv_sec > ts_dest->tv_sec)
			|| ((tv_end->tv_sec == ts_dest->tv_sec)
				&& ((tv_end->tv_usec * 1000) > ts_dest->tv_nsec)))
	{
		ts_dest->tv_sec  = 0;
		ts_dest->tv_nsec = 0;
		return;
	}

	ts_dest->tv_sec = ts_dest->tv_sec - tv_end->tv_sec;
	ts_dest->tv_nsec = ts_dest->tv_nsec - (tv_end->tv_usec * 1000);
	time_normalize (ts_dest);
}

int main (int argc, char **argv)
{
	pingobj_t      *ping;
	pingobj_iter_t *iter;

	struct sigaction sigint_action;

	struct timeval  tv_begin;
	struct timeval  tv_end;
	struct timespec ts_wait;
	struct timespec ts_int;

	int optind;
	int i;

	if (geteuid () != 0)
	{
		fprintf (stderr, "Need superuser privileges to open a RAW socket. Sorry.\n");
		return (1);
	}

	optind = read_options (argc, argv);

	if (optind >= argc)
		usage_exit (argv[0]);

	if ((ping = ping_construct ()) == NULL)
	{
		fprintf (stderr, "ping_construct failed\n");
		return (1);
	}

	{
		double temp_sec;
		double temp_nsec;

		temp_nsec = modf (opt_interval, &temp_sec);
		ts_int.tv_sec  = (time_t) temp_sec;
		ts_int.tv_nsec = (long) (temp_nsec * 1000000000L);

		/* printf ("ts_int = %i.%09li\n", (int) ts_int.tv_sec, ts_int.tv_nsec); */
	}

	if (opt_addrfamily != PING_DEF_AF)
		ping_setopt (ping, PING_OPT_AF, (void *) &opt_addrfamily);

	for (i = optind; i < argc; i++)
	{
		if (ping_host_add (ping, argv[i]) > 0)
		{
			fprintf (stderr, "ping_host_add (%s) failed\n", argv[i]);
			continue;
		}
	}

	for (iter = ping_iterator_get (ping);
			iter != NULL;
			iter = ping_iterator_next (iter))
	{
		ping_context_t *context;
		size_t buffer_size;

		context = context_create ();

		buffer_size = sizeof (context->host);
		ping_iterator_get_info (iter, PING_INFO_HOSTNAME, context->host, &buffer_size);

		buffer_size = sizeof (context->addr);
		ping_iterator_get_info (iter, PING_INFO_ADDRESS, context->addr, &buffer_size);

		ping_iterator_set_context (iter, (void *) context);
	}

	memset (&sigint_action, '\0', sizeof (sigint_action));
	sigint_action.sa_handler = sigint_handler;
	if (sigaction (SIGINT, &sigint_action, NULL) < 0)
	{
		perror ("sigaction");
		return (1);
	}

	while (opt_count != 0)
	{
		int status;

		if (gettimeofday (&tv_begin, NULL) < 0)
		{
			perror ("gettimeofday");
			return (1);
		}

		if (ping_send (ping) < 0)
		{
			fprintf (stderr, "ping_send failed\n");
			return (1);
		}

		for (iter = ping_iterator_get (ping);
				iter != NULL;
				iter = ping_iterator_next (iter))
		{
			print_host (iter);
		}
		fflush (stdout);

		/* Don't sleep in the last iteration */
		if (opt_count == 1)
			break;

		if (gettimeofday (&tv_end, NULL) < 0)
		{
			perror ("gettimeofday");
			return (1);
		}

		time_calc (&ts_wait, &ts_int, &tv_begin, &tv_end);

		/* printf ("Sleeping for %i.%09li seconds\n", (int) ts_wait.tv_sec, ts_wait.tv_nsec); */
		while ((status = nanosleep (&ts_wait, &ts_wait)) != 0)
		{
			if (errno != EINTR)
			{
				perror ("nanosleep");
				break;
			}
			else if (opt_count == 0)
			{
				/* sigint */
				break;
			}
		}

		if (opt_count > 0)
			opt_count--;
	} /* while (opt_count != 0) */

	for (iter = ping_iterator_get (ping);
			iter != NULL;
			iter = ping_iterator_next (iter))
	{
		ping_context_t *context;

		context = ping_iterator_get_context (iter);

		printf ("\n--- %s ping statistics ---\n"
				"%i packets transmitted, %i received, %.2f%% packet loss, time %.1fms\n"
				"rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
				context->host, context->req_sent, context->req_rcvd,
				100.0 * (context->req_sent - context->req_rcvd) / ((double) context->req_sent),
				context->latency_total,
				context->latency_min,
				context->latency_total / ((double) context->req_rcvd),
				context->latency_max,
				0.00);

		ping_iterator_set_context (iter, NULL);
		free (context);
	}

	ping_destroy (ping);

	return (0);
}
