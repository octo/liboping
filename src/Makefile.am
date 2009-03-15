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
liboping_la_LDFLAGS = -version-info 1:0:1
if BUILD_WITH_LIBSOCKET
liboping_la_LDFLAGS += -lsocket
endif
liboping_la_SOURCES = oping.h liboping.c

bin_PROGRAMS = oping

oping_SOURCES = oping.c
oping_LDADD = liboping.la
oping_LDFLAGS = -lm
if BUILD_WITH_LIBRT
oping_LDFLAGS += -lrt
endif
