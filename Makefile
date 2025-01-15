DEPS_FILES := \
	ML-DSA-Module-2024.asn \
	./examples/mldsa44-no-signed-attrs.pem \
	./examples/mldsa44-no-signed-attrs.txt \
	./examples/mldsa44-signed-attrs.pem \
	./examples/mldsa44-signed-attrs.txt \
	./examples/mldsa65-no-signed-attrs.pem \
	./examples/mldsa65-no-signed-attrs.txt \
	./examples/mldsa65-signed-attrs.pem \
	./examples/mldsa65-signed-attrs.txt \
	./examples/mldsa87-no-signed-attrs.pem \
	./examples/mldsa87-no-signed-attrs.txt \
	./examples/mldsa87-signed-attrs.pem \
	./examples/mldsa87-signed-attrs.txt \

LIBDIR := lib
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update --init
else
ifneq (,$(wildcard $(ID_TEMPLATE_HOME)))
	ln -s "$(ID_TEMPLATE_HOME)" $(LIBDIR)
else
	git clone -q --depth 10 -b main \
	    https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
endif
