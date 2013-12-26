EXTRA_DIST = perl/Changes perl/MANIFEST perl/META.yml perl/Makefile.PL \
		perl/Oping.xs perl/README perl/lib/Net/Oping.pm perl/t/Oping.t \
		perl/typemap

all-local: @BINDINGS@
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) all )

install-exec-local:
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) install )

clean-local:
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) realclean )

test:
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) test )

perl: perl-bindings

perl-bindings: perl/Makefile
	cd perl && $(MAKE)

# Check if the `perl' directory exists in the _build_ directory. If not, copy
# the files from the _source_ directory.
perl/Makefile: perl/Makefile.PL $(top_builddir)/config.status
	if test ! -d perl; then \
		for file in $(EXTRA_DIST); do \
			mkdir -p `dirname $$file`; \
			cp $(srcdir)/$$file `dirname $$file`; \
		done \
	fi
	cd perl && @PERL@ Makefile.PL PREFIX="$(prefix)" TOP_BUILDDIR="$(top_builddir)" TARGET_LIBDIR="$(libdir)" @PERL_BINDINGS_OPTIONS@

.PHONY: perl perl-bindings

