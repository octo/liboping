# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([liboping],[1.7.0],[ff@octo.it],,[http://github.com/octo/liboping/])
AC_CONFIG_SRCDIR([src/liboping.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([dist-bzip2])
AC_LANG([C])

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
LIBOPING_REVISION=10
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

# configure libtool
LT_INIT([dlopen])

# pkg-config interface
PKG_INSTALLDIR

AC_ARG_WITH(pkgconfigdir,
	    AC_HELP_STRING([--with-pkgconfigdir], [Use the specified pkgconfig dir (default is libdir/pkgconfig)]),
	    [pkgconfigdir="${withval}"],
	    [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST([pkgconfigdir])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([math.h signal.h fcntl.h inttypes.h netdb.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h locale.h langinfo.h])

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

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

LIBOPING_PC_LIBS_PRIVATE=''

socket_needs_socket="no"
AC_CHECK_FUNCS(socket, [],
	AC_CHECK_LIB(socket, socket,
		[socket_needs_socket="yes"],
		AC_MSG_ERROR(cannot find socket)))
if test "x$socket_needs_socket" = "xyes"; then
	LIBOPING_PC_LIBS_PRIVATE="${LIBOPING_PC_LIBS_PRIVATE} -lsocket"
fi

# Under Solaris, the `xnet' library provides `recvmsg' which complies with the
# X/Open CAE Specification.
with_libxnet="no"
AC_CHECK_LIB(xnet, __xnet_recvmsg, [with_libxnet="yes"],[])
if test "x$with_libxnet" = "xyes"
then
	CPPFLAGS="$CPPFLAGS -D_XPG4_2 -D__EXTENSIONS__"
fi
if test "x$with_libxnet" = "xyes"; then
	LIBOPING_PC_LIBS_PRIVATE="${LIBOPING_PC_LIBS_PRIVATE} -lxnet"
fi

AC_SUBST(LIBOPING_PC_LIBS_PRIVATE)

nanosleep_needs_rt="no"
AC_CHECK_FUNCS(nanosleep, [],
	AC_CHECK_LIB(rt, nanosleep,
		[nanosleep_needs_rt="yes"],
		AC_MSG_ERROR(cannot find nanosleep)))
AM_CONDITIONAL(BUILD_WITH_LIBRT, test "x$nanosleep_needs_rt" = "xyes")

with_ncurses="no"
AC_CHECK_HEADERS(ncursesw/ncurses.h ncurses.h, [with_ncurses="yes"], [])
if test "x$with_ncurses" = "xyes"
then
	have_ncursesw="no"
	have_ncurses="no"
	NCURSES_LIB=""

	AC_CHECK_LIB(ncursesw, mvwprintw, [have_ncursesw="yes"], [have_ncursesw="no"])
	AC_CHECK_LIB(ncurses, mvwprintw, [have_ncurses="yes"], [have_ncurses="no"])

	if test "x$have_ncursesw" = "xyes"; then
		NCURSES_LIB="-lncursesw"
	else if test "x$have_ncurses" = "xyes"; then
		NCURSES_LIB="-lncurses"
	else
		with_ncurses="no"
	fi; fi
	AC_SUBST(NCURSES_LIB)
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

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([gettimeofday memset modf select socket sqrt strcasecmp strdup strerror strncasecmp strtoul])

AC_CONFIG_FILES([Makefile src/Makefile src/liboping.pc src/mans/Makefile bindings/Makefile])
AC_OUTPUT
