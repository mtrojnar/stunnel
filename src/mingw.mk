## mingw/mingw64 Makefile
# by Michal Trojnara 2015-2016

# 32-bit Windows
#win32_targetcpu=i686
#win32_mingw=mingw

# 64-bit Windows
#win32_targetcpu=x86_64
#win32_mingw=mingw64

bindir = ../bin/$(win32_mingw)
objdir = ../obj/$(win32_mingw)

win32_ssl_dir = /opt/openssl-$(win32_mingw)
win32_cppflags = -I$(win32_ssl_dir)/include
win32_cflags = -mthreads -fstack-protector -O2
win32_cflags += -Wall -Wextra -Wpedantic -Wformat=2 -Wconversion -Wno-long-long
win32_cflags += -D_FORTIFY_SOURCE=2 -DUNICODE -D_UNICODE
win32_ldflags = -mthreads -fstack-protector -s

win32_common_libs = -lws2_32
win32_ssl_libs = -L$(win32_ssl_dir)/lib -lcrypto -lssl
win32_gui_libs = $(win32_common_libs) -lgdi32 -lpsapi $(win32_ssl_libs)
win32_cli_libs = $(win32_common_libs) $(win32_ssl_libs)

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

$(objdir)/%.o: $(srcdir)/%.c $(common_headers)
	$(win32_cc) -c $(win32_cppflags) $(win32_cflags) -o $@ $<

$(objdir)/resources.o: $(srcdir)/resources.rc $(srcdir)/resources.h $(srcdir)/version.h
	$(win32_windres) --include-dir $(srcdir) $< $@
