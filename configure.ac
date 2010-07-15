AC_INIT(liboping, 1.4.0)
AC_CONFIG_SRCDIR(src/liboping.c)
AC_CONFIG_HEADERS(src/config.h)
AM_INIT_AUTOMAKE(dist-bzip2)
AC_LANG(C)

AC_PREFIX_DEFAULT("/opt/oping")

# API version
LIBOPING_MAJOR=`echo $PACKAGE_VERSION | cut -d'.' -f1`
LIBOPING_MINOR=`echo $PACKAGE_VERSION | cut -d'.' -f2`
LIBOPING_PATCH=`echo $PACKAGE_VERSION | cut -d'.' -f3`
AC_SUBST(LIBOPING_MAJOR)
AC_SUBST(LIBOPING_MINOR)
AC_SUBST(LIBOPING_PATCH)

# ABI version
LIBOPING_CURRENT=2
LIBOPING_REVISION=3
LIBOPING_AGE=2
AC_SUBST(LIBOPING_CURRENT)
AC_SUBST(LIBOPING_REVISION)
AC_SUBST(LIBOPING_AGE)

#
# Check for programs/utilities
#
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_CONDITIONAL(COMPILER_IS_GCC, test "x$GCC" = "xyes")

if test "x$PERL" = "x"
then
	PERL="perl"
fi
AC_ARG_VAR(PERL, [Perl interpreter command])

#
# configure libtool
#
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL
#AC_PROG_RANLIB

#
# Checks for header files.
#
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(math.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(sys/stat.h)
AC_HEADER_TIME
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(signal.h)

# This sucks, but what can I do..?
AC_CHECK_HEADERS(netinet/in_systm.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
])
AC_CHECK_HEADERS(netinet/in.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
])
AC_CHECK_HEADERS(netinet/ip.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
])
AC_CHECK_HEADERS(netinet/ip_icmp.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
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
])
AC_CHECK_HEADERS(netinet/ip_var.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
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
])
AC_CHECK_HEADERS(netinet/ip6.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
])
AC_CHECK_HEADERS(netinet/icmp6.h, [], [],
[#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
#endif
])

socket_needs_socket="no"
AC_CHECK_FUNCS(socket, [],
	AC_CHECK_LIB(socket, socket,
		[socket_needs_socket="yes"],
		AC_MSG_ERROR(cannot find socket)))
AM_CONDITIONAL(BUILD_WITH_LIBSOCKET, test "x$socket_needs_socket" = "xyes")

# Under Solaris, the `xnet' library provides `recvmsg' which complies with the
# X/Open CAE Specification.
with_libxnet="no"
AC_CHECK_LIB(xnet, __xnet_recvmsg, [with_libxnet="yes"],[])
if test "x$with_libxnet" = "xyes"
then
	CPPFLAGS="$CPPFLAGS -D_XPG4_2 -D__EXTENSIONS__"
fi
AM_CONDITIONAL(BUILD_WITH_LIBXNET, test "x$with_libxnet" = "xyes")

nanosleep_needs_rt="no"
AC_CHECK_FUNCS(nanosleep, [],
	AC_CHECK_LIB(rt, nanosleep,
		[nanosleep_needs_rt="yes"],
		AC_MSG_ERROR(cannot find nanosleep)))
AM_CONDITIONAL(BUILD_WITH_LIBRT, test "x$nanosleep_needs_rt" = "xyes")

with_ncurses="yes"
AC_CHECK_HEADERS(ncurses.h, [with_ncurses="yes"], [with_ncurses="no"])
if test "x$with_ncurses" = "xyes"
then
	AC_CHECK_LIB(ncurses, mvwprintw, [with_ncurses="yes"], [with_ncurses="no"])
fi
AM_CONDITIONAL(BUILD_WITH_LIBNCURSES, test "x$with_ncurses" = "xyes")

AC_FUNC_STRERROR_R

AC_ARG_ENABLE(debug, [AS_HELP_STRING([--enable-debug], [Enable extensive debugging output.])],
[
	if test "x$enable_debug" = "xyes"
	then
		AC_DEFINE(WITH_DEBUG, 1, [Define to 1 if you want to get debugging output.])
	fi
], [])
AM_CONDITIONAL(BUILD_WITH_DEBUG, test "x$enable_debug" = "xyes")

pcap_config_path="pcap-config"
AC_ARG_WITH(libpcap, [AS_HELP_STRING([--with-libpcap@<:@=OPTIONS@:>@], [Set the path to the PCAP library.])],
[
	if test "x$withval" != "xno" && test "x$withval" != "xyes"
	then
		if test -x "$withval"
		then
			pcap_config_path="$withval"
			with_pcap="yes"
		else if test -x "$withval/bin/pcap-config"
		then
			pcap_config_path="$withval/bin/pcap-config"
			with_pcap="yes"
		else
			AC_MSG_WARN([Argument of "--with-pcap" does not point to "pcap-config"]);
			with_pcap="no"
		fi; fi
	fi
], [with_pcap="yes"])

if test "x$with_pcap" = "xyes"
then
	with_pcap_cppflags=`"$pcap_config_path" --cflags`
	if test $? != 0
	then
		with_pcap="no"
	fi
fi

if test "x$with_pcap" = "xyes"
then
	with_pcap_ldflags=`"$pcap_config_path" --libs`
	if test $? != 0
	then
		with_pcap="no"
	fi
fi

SAVE_CPPFLAGS="$CPPFLAGS"
SAVE_LDFLAGS="$LDFLAGS"
CPPFLAGS="$CPPFLAGS $with_pcap_cppflags"
LDFLAGS="$LDFLAGS $with_pcap_ldflags"

if test "x$with_pcap" = "xyes"
then
	AC_CHECK_HEADERS(pcap.h, [with_pcap="yes"], [with_pcap="no"])
fi
if test "x$with_pcap" = "xyes"
then
	AC_CHECK_LIB(pcap, pcap_open_live, [with_pcap="yes"], [with_pcap="no"])
fi

CPPFLAGS="$SAVE_CPPFLAGS"
LDFLAGS="$SAVE_LDFLAGS"

if test "x$with_pcap" = "xyes"
then
	WITH_LIBPCAP_CPPFLAGS="$with_pcap_cppflags"
	WITH_LIBPCAP_LDFLAGS="$with_pcap_ldflags"
	AC_SUBST(WITH_LIBPCAP_CPPFLAGS)
	AC_SUBST(WITH_LIBPCAP_LDFLAGS)
	AC_DEFINE(HAVE_LIBPCAP, 1, [Define to 1 if you have the pcap library.])
fi
AM_CONDITIONAL(BUILD_WITH_LIBPCAP, test "x$with_pcap" = "xyes")

libnet_config_path="libnet-config"
AC_ARG_WITH(libnet, [AS_HELP_STRING([--with-libnet@<:@=OPTIONS@:>@], [Set the path to the libnet library.])],
[
	if test "x$withval" != "xno" && test "x$withval" != "xyes"
	then
		if test -x "$withval"
		then
			libnet_config_path="$withval"
			with_libnet="yes"
		else if test -x "$withval/bin/libnet-config"
		then
			libnet_config_path="$withval/bin/libnet-config"
			with_libnet="yes"
		else
			AC_MSG_WARN([Argument of "--with-libnet" does not point to "libnet-config"]);
			with_libnet="no"
		fi; fi
	fi
], [with_libnet="yes"])

if test "x$with_libnet" = "xyes"
then
	with_libnet_cppflags=`"$libnet_config_path" --cflags`
	if test $? != 0
	then
		with_libnet="no"
	fi
fi

if test "x$with_libnet" = "xyes"
then
	with_libnet_ldflags=`"$libnet_config_path" --libs`
	if test $? != 0
	then
		with_libnet="no"
	fi
fi

SAVE_CPPFLAGS="$CPPFLAGS"
SAVE_LDFLAGS="$LDFLAGS"
CPPFLAGS="$CPPFLAGS $with_libnet_cppflags"
LDFLAGS="$LDFLAGS $with_libnet_ldflags"

if test "x$with_libnet" = "xyes"
then
	AC_CHECK_HEADERS(libnet.h, [with_libnet="yes"], [with_libnet="no"])
fi
if test "x$with_libnet" = "xyes"
then
	AC_CHECK_LIB(net, libnet_init, [with_libnet="yes"], [with_libnet="no"])
fi

CPPFLAGS="$SAVE_CPPFLAGS"
LDFLAGS="$SAVE_LDFLAGS"

if test "x$with_libnet" = "xyes"
then
	WITH_LIBNET_CPPFLAGS="$with_libnet_cppflags"
	WITH_LIBNET_LDFLAGS="$with_libnet_ldflags"
	AC_SUBST(WITH_LIBNET_CPPFLAGS)
	AC_SUBST(WITH_LIBNET_LDFLAGS)
	AC_DEFINE(HAVE_LIBNET, 1, [Define to 1 if you have the libnet library.])
fi
AM_CONDITIONAL(BUILD_WITH_LIBNET, test "x$with_libnet" = "xyes")

AC_ARG_ENABLE(arp, [AS_HELP_STRING([--disable-arp], [Disable ARP ping support.])], [],
[
	if test "x$with_pcap" = "xyes" && test "x$with_libnet" = "xyes"
	then
		with_arp="yes"
	else
		with_arp="no"
	fi
])
if test "x$with_arp" = "xyes"
then
	AC_DEFINE(ENABLE_ARP, 1, [Define to 1 if you want to have arp ping support.])
fi
AM_CONDITIONAL(BUILD_WITH_ARP, test "x$with_arp" = "xyes")

AC_ARG_WITH(perl-bindings, [AS_HELP_STRING([--with-perl-bindings@<:@=OPTIONS@:>@], [Options passed to "perl Makefile.PL".])],
[
	if test "x$withval" != "xno" && test "x$withval" != "xyes"
	then
		PERL_BINDINGS_OPTIONS="$withval"
		with_perl_bindings="yes"
	else
		PERL_BINDINGS_OPTIONS=""
		with_perl_bindings="$withval"
	fi
],
[
	PERL_BINDINGS_OPTIONS=""
	with_perl_bindings="yes"
])

if test "x$with_perl_bindings" = "xyes"
then
	BINDINGS="perl-bindings"
else
	BINDINGS=""
fi

AC_SUBST(PERL_BINDINGS_OPTIONS)

AC_SUBST(BINDINGS)

AC_OUTPUT(Makefile src/Makefile src/mans/Makefile bindings/Makefile)
