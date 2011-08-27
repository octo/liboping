AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = mans

if COMPILER_IS_GCC
AM_CFLAGS = -Wall -Werror
endif

include_HEADERS = oping.h
lib_LTLIBRARIES = liboping.la

# version-info: current:revision:age
#
# * If the library source code has changed at all since the last update, then
#   increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# * If any interfaces have been added, removed, or changed since the last
#   update, increment current, and set revision to 0.
# * If any interfaces have been added since the last public release, then
#   increment age.
# * If any interfaces have been removed since the last public release, then
#   set age to 0. 
#
# <http://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html>
liboping_la_SOURCES = oping.h liboping.c

liboping_la_CPPFLAGS = $(AM_CPPFLAGS)
liboping_la_LDFLAGS = $(AM_LDFLAGS) -version-info @LIBOPING_CURRENT@:@LIBOPING_REVISION@:@LIBOPING_AGE@
liboping_la_LIBADD =
if BUILD_WITH_LIBSOCKET
liboping_la_LIBADD += -lsocket
endif
if BUILD_WITH_LIBXNET
liboping_la_LIBADD += -lxnet
endif

bin_PROGRAMS = oping

oping_SOURCES = oping.c
oping_LDADD = liboping.la -lm
if BUILD_WITH_LIBRT
oping_LDADD += -lrt
endif

if BUILD_WITH_LIBNCURSES
bin_PROGRAMS += noping

noping_SOURCES = oping.c
noping_CPPFLAGS = $(AM_CPPFLAGS) -DUSE_NCURSES=1
noping_LDADD = liboping.la -lm -lncurses
if BUILD_WITH_LIBRT
noping_LDADD += -lrt
endif
endif # BUILD_WITH_LIBNCURSES

install-exec-hook:
	@if test "x0" = "x$$UID"; then \
		if test "xLinux" = "x`uname -s`"; then \
			echo "Setting CAP_NET_RAW capability on binaries."; \
			setcap cap_net_raw=ep $(DESTDIR)$(bindir)/oping || true; \
			setcap cap_net_raw=ep $(DESTDIR)$(bindir)/noping || true; \
		else \
			echo "Setting set-UID bit on binaries."; \
			chmod u+s $(DESTDIR)$(bindir)/oping || true; \
			chmod u+s $(DESTDIR)$(bindir)/noping || true; \
		fi; \
	fi
