################################################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ team                        #
#                                                                              #
# lulzbuster                                                                   #
# A very fast and smart web directory and file enumeration tool written in C.  #
#                                                                              #
# FILE                                                                         #
# Makefile                                                                     #
#                                                                              #
# AUTHOR                                                                       #
# noptrix@nullsecurity.net                                                     #
#                                                                              #
################################################################################


.EXPORT_ALL_VARIABLES:
	@echo "[-] ERROR: you need GNU make!"

VER = $(shell curl --version |head -1|cut -d ' ' -f 2|tr -d '.' 2>/dev/null)
ifeq ($(shell test $(VER) -lt 7680; echo $$?),0)
	CFLAGS += -DLAME
endif

DEBIAN = $(shell if egrep -i 'debian|ubuntu' /proc/version > /dev/null 2>&1; \
				 then echo 1 ; fi)
ifeq ($(DEBIAN), 1)
	ECHO = "echo"
else
	ECHO = "echo -e"
endif

RED=$(shell "${ECHO}" "\033[01;31;10m")
BLUE=$(shell "${ECHO}" "\033[01;34;10m")
NORM=$(shell "${ECHO}" "\033[0m")

define BANNER
    __      __      __               __
   / /_  __/ /___  / /_  __  _______/ /____  _____
  / / / / / /_  / / __ \/ / / / ___/ __/ _ \/ ___/
 / / /_/ / / / /_/ /_/ / /_/ (__  ) /_/  __/ /
/_/\__,_/_/ /___/_.___/\__,_/____/\__/\___/_/
endef

export BANNER

CC ?= cc
RM = rm -rf
MV = mv
CP = cp -r
MKDIR = mkdir -p
STRIP = strip

# OS detection for ld + strip flag dialects. linux = GNU binutils,
# darwin = apple's ld + BSD strip, *BSD = lld + elftoolchain (GNU-ish)
UNAME_S := $(shell uname -s)

DESTDIR = /usr/local
INSTDIR = $(DESTDIR)/bin
SHAREDIR = $(DESTDIR)/share/lulzbuster
DOCDIR = $(DESTDIR)/share/doc/lulzbuster
LICENSEDIR = $(DESTDIR)/share/licenses/lulzbuster
MANDIR = $(DESTDIR)/share/man/man1

INCDIR = inc
SRCDIR = src

# release build: lean + fast. uncomment the dev block below for ASan + debug
CFLAGS += -W -Wall -Wextra -O2 -pthread -I $(INCDIR)
CFLAGS += -MMD -MP
CFLAGS += -flto -fno-plt -pipe -DNDEBUG
CFLAGS += -ffunction-sections -fdata-sections

# *BSD installs ports/pkgs (incl. libcurl) under /usr/local. cc doesn't
# search there by default, so add the include path now (LDFLAGS' -L is
# appended further down once LDFLAGS itself is initialized)
ifneq (,$(filter FreeBSD OpenBSD NetBSD DragonFly,$(UNAME_S)))
  CFLAGS += -I/usr/local/include
endif

# dev/debug build (uncomment to enable). includes ASan, fortify-source,
# stack protector, RELRO/now, full debug info. slower + larger but
# catches memory bugs and gives readable backtraces
#CFLAGS += -W -Wall -Wextra -O2 -g -g3 -ggdb -fstack-protector-all -fPIE -fPIC
#CFLAGS += -pthread -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro
#CFLAGS += -fsanitize=address -I $(INCDIR)
#CFLAGS += -MMD -MP

# linker dead-code stripping: GNU/BSD use --gc-sections, macOS uses
# -dead_strip (apple's ld doesn't grok --gc-sections)
LDFLAGS = -lcurl -flto
ifeq ($(UNAME_S),Darwin)
  LDFLAGS += -Wl,-dead_strip
else
  LDFLAGS += -Wl,--gc-sections
endif

# *BSD libcurl lives under /usr/local/lib (see CFLAGS path comment above)
ifneq (,$(filter FreeBSD OpenBSD NetBSD DragonFly,$(UNAME_S)))
  LDFLAGS += -L/usr/local/lib
endif

# strip flag dialect: GNU binutils on linux supports the long options +
# section -R; macOS/*BSD strip is leaner so we just strip debug syms
ifeq ($(UNAME_S),Linux)
  STRIP_FLAGS = -s -g -S -d --strip-debug --strip-dwo --strip-unneeded \
                -R .comment -R .gnu.version -R .gnu_debuglink \
                -R .note.ABI-tag -R .note.gnu.build-id -R .note.gnu.property
else
  STRIP_FLAGS = -S
endif

OBJS = $(SRCDIR)/lulzbuster.o $(SRCDIR)/help.o $(SRCDIR)/checks.o
OBJS += $(SRCDIR)/wrapper.o $(SRCDIR)/error.o $(SRCDIR)/opts.o $(SRCDIR)/http.o
OBJS += $(SRCDIR)/misc.o $(SRCDIR)/thpool.o $(SRCDIR)/attack.o
OBJS += $(SRCDIR)/signals.o $(SRCDIR)/session.o $(SRCDIR)/log.o
DEPS = $(OBJS:.o=.d)

# silently include the per-object header-dep files. on a clean tree they
# don't exist yet (leading - swallows the warning); the first compile
# generates them and subsequent rebuilds pick up header changes
-include $(DEPS)

$(SRCDIR)%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

default:
	@echo "${BLUE}$${BANNER}${NORM}"
	@echo
	@echo "        --==[ by nullsecurity.net ]==--"
	@echo
	@echo "${RED}[-]${NORM} unknown make option. available:"
	@echo
	@echo "    > make lulzbuster  - build lulzbuster"
	@echo "    > make install     - install lulzbuster"
	@echo "    > make uninstall   - uninstall lulzbuster"
	@echo "    > make clean       - clean everything"

lulzbuster: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	$(STRIP) $(STRIP_FLAGS) lulzbuster

install:
	$(MKDIR) $(INSTDIR)
	$(MKDIR) $(SHAREDIR)
	$(MKDIR) $(DOCDIR)
	$(MKDIR) $(LICENSEDIR)
	$(MKDIR) $(MANDIR)
	$(CP) lists $(SHAREDIR)/lists
	$(CP) docs/LICENSE $(LICENSEDIR)/
	$(CP) docs/* $(DOCDIR)/
	$(RM) $(DOCDIR)/LICENSE $(DOCDIR)/lulzbuster.1
	$(CP) docs/lulzbuster.1 $(MANDIR)/
	$(MV) lulzbuster $(INSTDIR)/

uninstall:
	$(RM) $(INSTDIR)/lulzbuster $(SHAREDIR) $(DOCDIR) $(LICENSEDIR) \
		$(MANDIR)/lulzbuster.1

clean:
	$(RM) lulzbuster $(SRCDIR)/*.o $(SRCDIR)/*.d *.core core *vgcore*

