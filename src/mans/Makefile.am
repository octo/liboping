man_PODS = liboping.pod ping_construct.pod ping_setopt.pod ping_host_add.pod \
	   ping_send.pod ping_get_error.pod ping_iterator_get.pod \
	   ping_iterator_get_info.pod ping_iterator_get_context.pod oping.pod
man_MANS = liboping.3 ping_construct.3 ping_setopt.3 ping_host_add.3 \
	   ping_send.3 ping_get_error.3 ping_iterator_get.3 \
	   ping_iterator_get_info.3 ping_iterator_get_context.3 oping.8

EXTRA_DIST = $(man_MANS) $(man_PODS)

.pod.1:
	pod2man --section=1 --release=$(VERSION) --center=$(PACKAGE) $< >$@

.pod.3:
	pod2man --section=3 --release=$(VERSION) --center=$(PACKAGE) $< >$@

.pod.8:
	pod2man --section=8 --release=$(VERSION) --center=$(PACKAGE) $< >$@
