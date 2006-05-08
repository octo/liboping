AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = mans

if COMPILER_IS_GCC
AM_CFLAGS = -Wall -Werror
endif

include_HEADERS = oping.h
lib_LTLIBRARIES = liboping.la

#liboping_la_CFLAGS = 
liboping_la_LDFLAGS = -avoid-version
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
