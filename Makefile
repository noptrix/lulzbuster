################################################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ team                        #
#                                                                              #
# lulzbuster                                                                   #
# A very fast and smart web-dir/file enumeration tool written in C.            #
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

RED=$(shell "${ECHO}" "\033[01;91m")
BLUE=$(shell "${ECHO}" "\033[01;94m")
NORM=$(shell "${ECHO}" "\033[0m")

define BANNER
    __      __      __               __
   / /_  __/ /___  / /_  __  _______/ /____  _____
  / / / / / /_  / / __ \/ / / / ___/ __/ _ \/ ___/
 / / /_/ / / / /_/ /_/ / /_/ (__  ) /_/  __/ /
/_/\__,_/_/ /___/_.___/\__,_/____/\__/\___/_/
endef

export BANNER

CC = gcc
RM = rm -rf
MV = mv
CP = cp -r
MKDIR = mkdir -p
STRIP = strip

DESTDIR = /usr/local
INSTDIR = $(DESTDIR)/bin
SHAREDIR = $(DESTDIR)/share/lulzbuster
DOCDIR = $(DESTDIR)/share/doc/lulzbuster
LICENSEDIR = $(DESTDIR)/share/licenses/lulzbuster

INCDIR = inc
SRCDIR = src

CFLAGS += -W -Wall -Wextra -O2 -pthread -I $(INCDIR)
#CFLAGS += -W -Wall -Wextra -O2 -g -g3 -ggdb -fstack-protector-all -fPIE -fPIC
#CFLAGS += -pthread -D_FORTIFY_SOURCE=2 -Wl,-z,now -Wl,-z,relro
#CFLAGS += -fsanitize=address -I $(INCDIR)

LDFLAGS = -lcurl

OBJS = $(SRCDIR)/lulzbuster.o $(SRCDIR)/help.o $(SRCDIR)/checks.o
OBJS += $(SRCDIR)/wrapper.o $(SRCDIR)/error.o $(SRCDIR)/opts.o $(SRCDIR)/http.o
OBJS += $(SRCDIR)/misc.o $(SRCDIR)/thpool.o $(SRCDIR)/attack.o
OBJS += $(SRCDIR)/signals.o

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
	$(STRIP) -R .gnu.version -R .note.gnu.build-i -R .note.ABI-tag -g -S -d \
		--strip-debug --strip-dwo -s lulzbuster

install:
	$(MKDIR) $(INSTDIR)
	$(MKDIR) $(SHAREDIR)
	$(MKDIR) $(DOCDIR)
	$(MKDIR) $(LICENSEDIR)
	$(CP) lists $(SHAREDIR)/lists
	$(CP) docs/LICENSE $(LICENSEDIR)/
	$(CP) docs/* $(DOCDIR)/
	$(RM) $(DOCDIR)/LICENSE
	$(MV) lulzbuster $(INSTDIR)/

uninstall:
	$(RM) $(INSTDIR)/lulzbuster $(SHAREDIR) $(DOCDIR) $(LICENSEDIR)

clean:
	$(RM) lulzbuster $(SRCDIR)/*.o *.core core *vgcore*

