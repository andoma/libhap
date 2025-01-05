PROG=hap

SRCS += src/hap.c \
	src/hap_pairing.c \
	src/hap_network.c \
	src/hap_convenience.c \
	src/buf.c \
	src/http_parser.c \
	src/intvec.c \

O ?= build

SONAME=libhap.so.0

PREFIX ?= /usr/local

CFLAGS  += -std=gnu99 -O2 -Wall -Werror -Wno-unused-function -g
CFLAGS += -Wno-deprecated-declarations
CFLAGS  += $(shell pkg-config --cflags libcrypto avahi-client)
LDFLAGS += $(shell pkg-config --libs libcrypto avahi-client)
LDFLAGS += -lpthread

ifeq (${ASAN},1)
O = build.asan
CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address
PROG = hap.asan
endif

CFLAGS_shared = -fvisibility=hidden -fPIC -shared -DHAP_SHARED_OBJECT_BUILD

OBJS =  $(SRCS:%.c=$(O)/%.o)
DEPS =  ${OBJS:%.o=%.d}

${PROG}: ${OBJS} src/main.c Makefile
	@mkdir -p $(dir $@)
	${CC} ${CFLAGS} -o $@ ${OBJS} src/main.c ${LDFLAGS}

${O}/%.o: %.c Makefile | checkextdeps
	@mkdir -p $(dir $@)
	${CC} -MD ${CFLAGS} -c -o $@ $<

${O}/${SONAME}: ${SRCS} Makefile
	@mkdir -p $(dir $@)
	${CC} -Wl,-soname,${SONAME} -Wl,--no-undefined ${CFLAGS} ${CFLAGS_shared} -o $@ ${SRCS} ${LDFLAGS}
	strip --strip-all --discard-all $@

solib: ${O}/${SONAME}

install: ${O}/${SONAME}
	@mkdir -p "${PREFIX}/include/libhap" "${PREFIX}/lib/"
	cp src/hap.h "${PREFIX}/include/libhap/"
	cp "${O}/${SONAME}" "${PREFIX}/lib/"
	ln -srf "${PREFIX}/lib/${SONAME}" "${PREFIX}/lib/libhap.so"
	if [ "x`id -u $$USER`" = "x0" ]; then ldconfig ; fi

uninstall:
	rm -rf "${PREFIX}/lib/libhap.so" "${PREFIX}/lib/${SONAME}" "${PREFIX}/include/libhap"


checkextdeps:
	@which pkg-config >/dev/null || (echo "\nDependency unmet: Need pkg-config\n" && exit 1)
	@pkg-config --atleast-version=1.1.1 libcrypto || (echo "\nDependency unmet: Need at least openssl >= 1.1.1\n" && exit 1)
	@pkg-config avahi-client || (echo "\nDependency unmet: Need avahi-client\n" && exit 1)

-include $(DEPS)
