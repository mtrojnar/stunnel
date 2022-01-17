## mingw/mingw64 Makefile
# by Michal Trojnara 1998-2022

# 32-bit Windows
#win32_arch=win32
#win32_targetcpu=i686
#win32_mingw=mingw

# 64-bit Windows
#win32_arch=win64
#win32_targetcpu=x86_64
#win32_mingw=mingw64

bindir = ../bin/$(win32_arch)
objdir = ../obj/$(win32_arch)

ifeq ($(win32_ssl_dir),)
win32_ssl_dir := /opt/openssl-$(win32_mingw)
endif
win32_cppflags = -I$(win32_ssl_dir)/include
win32_cflags = -g -mthreads -O2
win32_cflags += -fstack-protector
win32_cflags += -Wall -Wextra -Wpedantic -Wconversion -Wno-long-long -ansi
win32_cflags += -D_FORTIFY_SOURCE=2 -DUNICODE -D_UNICODE
win32_ldflags = -g -mthreads -pipe
win32_ldflags += -fstack-protector
win32_ldflags += -Wl,--dynamicbase,--nxcompat,--no-seh,--tsaware,--no-insert-timestamp
ifeq ($(win32_arch),win64)
win32_ldflags += -Wl,--high-entropy-va
else
win32_ldflags += -Wl,--large-address-aware
endif

# -fstack-protector was broken in x86_64-w64-mingw32-gcc 8.2.0

# compiling with -D_FORTIFY_SOURCE=2 may require linking with -lssp
win32_common_libs = -lws2_32 -lkernel32 -lssp
ifneq (,$(wildcard $(win32_ssl_dir)/lib64/libcrypto.dll.a))
    # use OpenSSL 3.x.x mingw-generated library stubs if available
    win32_ssl_libs = -L$(win32_ssl_dir)/lib64 -lcrypto -lssl
else ifneq (,$(wildcard $(win32_ssl_dir)/lib/libcrypto.dll.a))
    # use OpenSSL 1.x.x mingw-generated library stubs if available
    win32_ssl_libs = -L$(win32_ssl_dir)/lib -lcrypto -lssl
else
    # directly import libeay32.dll and ssleay32.dll otherwise
    win32_ssl_libs = -L$(win32_ssl_dir)/bin -llibeay32 -lssleay32
endif
win32_gui_libs = $(win32_common_libs) -lgdi32 -lpsapi $(win32_ssl_libs)
win32_cli_libs = $(win32_common_libs) $(win32_ssl_libs)

common_headers = common.h prototypes.h version.h
win32_common = tls str file client log options protocol network resolver
win32_common += ssl ctx verify sthreads fd dhparam cron stunnel
win32_gui = ui_win_gui resources
win32_cli = ui_win_cli
win32_common_objs = $(addsuffix .o, $(addprefix $(objdir)/, $(win32_common)))
win32_gui_objs = $(addsuffix .o, $(addprefix $(objdir)/, $(win32_gui)))
win32_cli_objs = $(addsuffix .o, $(addprefix $(objdir)/, $(win32_cli)))

win32_prefix = $(win32_targetcpu)-w64-mingw32-
win32_cc = $(win32_prefix)gcc
win32_windres = $(win32_prefix)windres

all: mkdirs $(bindir)/stunnel.exe $(bindir)/tstunnel.exe

mkdirs:
	mkdir -p $(bindir) $(objdir)

$(bindir)/stunnel.exe: $(win32_common_objs) $(win32_gui_objs)
	$(win32_cc) -mwindows $(win32_ldflags) -o $(bindir)/stunnel.exe $(win32_common_objs) $(win32_gui_objs) $(win32_gui_libs)

$(bindir)/tstunnel.exe: $(win32_common_objs) $(win32_cli_objs)
	$(win32_cc) $(win32_ldflags) -o $(bindir)/tstunnel.exe $(win32_common_objs) $(win32_cli_objs) $(win32_cli_libs)

$(objdir)/%.o: $(srcdir)/%.c
	$(win32_cc) -c $(win32_cppflags) $(win32_cflags) -o $@ $<

$(objdir)/%.o: $(common_headers)

$(win32_gui_objs): $(srcdir)/resources.h

$(objdir)/resources.o: $(srcdir)/resources.rc
	$(win32_windres) --include-dir $(srcdir) $< $@

$(objdir)/resources.o: $(srcdir)/version.h
