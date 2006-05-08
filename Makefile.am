SUBDIRS = libltdl src
INCLUDES = $(LTDLINCL)

EXTRA_DIST = debian

dist-hook:
	find $(distdir) -type d -name '.svn' | xargs rm -rf
