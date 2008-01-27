EXTRA_DIST = perl/Changes perl/MANIFEST perl/META.yml perl/Makefile.PL \
		perl/Oping.xs perl/README perl/lib/Net/Oping.pm perl/t/Oping.t \
		perl/typemap

all-local: @BINDINGS@

install-exec-local:
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) install )

clean-local:
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) realclean )

test:
	[ ! -f perl/Makefile ] || ( cd perl && $(MAKE) test )

perl-bindings: perl/Makefile
	cd perl && $(MAKE)

perl/Makefile: perl/Makefile.PL $(top_builddir)/config.status
	if test ! -d perl; then \
		for file in $(EXTRA_DIST); do \
			mkdir -p `dirname $$file`; \
			cp $(srcdir)/$$file `dirname $$file`; \
		done \
	fi
	
	cd perl && @PERL@ Makefile.PL PREFIX=$(prefix) @PERL_BINDINGS_OPTIONS@


.PHONY: perl-bindings

