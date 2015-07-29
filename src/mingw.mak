# Simple Makefile.w32 for stunnel.exe by Michal Trojnara 1998-2007
#
# Modified by Brian Hatch  (bri@stunnel.org)
# 20101030 pdelaage : added version.rc\.h management + HOST to customize version more precisely in Windows Explorer Property Sheet
#  general processing made close to vc.mak and evc.mak
# + multi-HOST management (if used on Windows host or Linux Host)
# + lack of gnu-win32 (rm) detection
# note: rm is used INTERNALLY by gcc for deletion if intermediate files.

# This makefile is only tested on the mingw compiler.  Mingw
# can successfully compile both openssl and stunnel.  If you want
# to use another compiler, give it a shot, and tell us how it went.

# pdelaage : THIS makefile can be used with mingw-make on Windows or gnu make on Linux,
# to produce the Win32 version of stunnel (target is win32).
# It requires, on Windows, the use of gnu-win32 tools: rm, mkdir, rmdir
# that manages files and dirs BOTH on linux and Windows with / as path separator.
# Note: Native windows equivalent, del and mkdir/rmdir, badly manage / and \, so they cannot be used
# here.
# so, on Windows host, download this : http://gnuwin32.sourceforge.net/downlinks/coreutils.php
# if you have forgotten this, this makefile will remind you...
 
# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you???)
#SSLDIR=../openssl-1.0.0d
SSLDIR=C:/Users/standard/Documents/Dvts/Contrib/openssl/v1.0.0c/patched3

# c:\, antislash is not correctly recognized by mingw32-make, produces some "missing separator" issue.

# pdelaage: simple trick to detect if we are using mingw-gcc on a Windows host, or on a linux host.
# windir is a system environment variable on windows NT and above...
# and then redefine some macros...
# note: ifdef is !IFDEF in MS nmake or Borland make...
#       $(info is !MESSAGE in MS nmake or Borland make...

ifdef windir
$(info  host machine is a Windows machine )
NULLDEV=NUL
MKDIR="C:\Program Files\GnuWin32\bin\mkdir.exe"
DELFILES="C:\Program Files\GnuWin32\bin\rm.exe" -f
DELDIR="C:\Program Files\GnuWin32\bin\rm.exe" -rf
else
$(info  host machine is a linux machine )
NULLDEV=/dev/null
MKDIR=mkdir
DELFILES=rm -f
DELDIR=rm -rf
endif

TARGETCPU=MGW32
SRC=../src
OBJROOT=../obj
OBJ=$(OBJROOT)/$(TARGETCPU)
BINROOT=../bin
BIN=$(BINROOT)/$(TARGETCPU)

#OBJS=stunnel.o ssl.o ctx.o verify.o file.o client.o protocol.o sthreads.o log.o options.o network.o resolver.o gui.o resources.o version.o str.c

OBJS=$(OBJ)/stunnel.o $(OBJ)/ssl.o $(OBJ)/ctx.o $(OBJ)/verify.o $(OBJ)/file.o $(OBJ)/client.o   \
	$(OBJ)/protocol.o $(OBJ)/sthreads.o $(OBJ)/log.o $(OBJ)/options.o $(OBJ)/network.o \
	$(OBJ)/resolver.o $(OBJ)/gui.o $(OBJ)/resources.o $(OBJ)\str.obj \
	$(OBJ)/version.o

CC=gcc
RC=windres

# pdelaage note:  as a workaround for windres bug on version.rc, equivalent to "use a temp file instead of popen" option between cpp and windres !
RCP=gcc -E -xc-header -DRC_INVOKED

# pdelaage: HOST is useful for version/properties management.
DEFINES=-DUSE_WIN32 -DHAVE_OPENSSL -DHOST=\"x86-pc-mingw32-gnu\" -D_WIN32_WINNT=0x0501
# pdelaage: if we target winver >= wxp, then we have access to winsock2/getaddrinfo defined in mingw/include/ws2tcpip ONLY
#  with this symbol -D_WIN32_WINNT=0x0501 (ie XP), BUT probably the stunnel.exe will run perfectly on w9x/2K. 
# !! This symbol is NOT required in MS VC or EVC includes. this is apparently specific to GNU-MINGW includes/libs!!!
# The MS doc says that getaddrinfo IS AVAILABLE since win95 (provided that we have the winsock2 patch of course) and WinCE 4.1 !!!!
# MORE note : if stunnel does not run appropriately on w9x/NT4, you MUST adapt resolver.c...not so difficult.

# Note about HOST: if not defined here, HOST will be defined as a string by common.h and this will break version.rc because, presently,
# it does not include common.h.

# some preprocessing debug : $(info  DEFINES is $(DEFINES) )

#CFLAGS=-g -O2 -Wall $(DEFINES) -I$(SSLDIR)/outinc
#pdelaage : outinc not correct, it is inc32!
CFLAGS=-g -O2 -Wall $(DEFINES) -I$(SSLDIR)/inc32

# RFLAGS, note of pdelaage: windres accepts -fo for compatibility with ms tools
# default options : -J rc -O coff, input rc file, output coff file.
# pdelaage BUG windres : does not understand correctly the -DHOST=\"XXX\", the dbl quotes ARE LOST
# at the interface between the gcc preprocessor and the windres compilation !
# a solution is to avoid popen for this interface! so use_temp_file in RFLAGS
# I did not find any trick at source level...except suppressing the <"> here and add them in the source with "QUOTME" or "STRINGIZE"
# but then it breaks some rules in common.h where the quotes are embedded in HOST symbol. and I did not want to break common.h...
# OTHER definitive solution if use-temp-file option does not exist anymore: proceed in two steps, pre-processing first,
# output in an intermediate file, and then windres, all this with 2 make inference rules.

RFLAGS=-v --use-temp-file $(DEFINES)
# following RFLAGS2 useful if one day use-temp-file does not exist anymore 
RFLAGS2=-v $(DEFINES)
LDFLAGS=-s

# LIBS=-L$(SSLDIR)/out -lssl -lcrypto -lwsock32 -lgdi32 -lcrypt32
#20101030 pdelaage fix winsock2 and BAD sslpath  ! LIBS=-L$(SSLDIR)/out -lzdll -leay32 -lssl32 -lwsock32 -lgdi32 -lcrypt32
# added libeay instead of eay, ssleay instead of ssl32, suppressed zdll useless.
LIBS=-L$(SSLDIR)/out32dll  -lssleay32 -llibeay32  -lws2_32 -lgdi32 -lcrypt32
# IMPORTANT pdelaage : restore this if you need (but I do not see why) -lzdll

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) -o$@ -c $<

$(OBJ)/%.o: $(SRC)/%.cpp
	$(CC) $(CFLAGS) -o$@ -c $<
	
$(OBJ)/%.o: $(SRC)/%.rc
	$(RC) $(RFLAGS) -o$@ $<

# pdelaage : trick for windres preprocessing popen bug on Windows, in case the windres option
# use_temp_file disappear one day...
# comment out the $(RC) rule above to activate the following 

$(OBJ)/%.rcp: $(SRC)/%.rc
	$(RCP) $(DEFINES) -o$@ $<
	
$(OBJ)/%.o: $(OBJ)/%.rcp
	$(RC) $(RFLAGS2) -o$@ $<

# Note : gnu-make will automatically RM the intermediate "rcp" file 
# BUT it will ABSOLUTELY NEED the "rm" command available : not a problem on linux
# but on a windows dev host machine, one will need to install gnu-win32/rm command
# in the system...
# for debug of the preprocessed rcp file, because it is automatically deleted by gnu-make:	cp $< $<.2

all: testenv makedirs $(BIN)/stunnel.exe

#pdelaage : testenv purpose is to detect, on windows, whether Gnu-win32 has been properly installed...
# a first call to "true" is made to detect availability, a second is made to stop the make process.
ifdef windir
testenv:
	-@ echo OFF
	-@ true >$(NULLDEV) 2>&1 || echo You MUST install Gnu-Win32 coreutils \
	from http://gnuwin32.sourceforge.net/downlinks/coreutils.php and set PATH to include C:\Program Files\GnuWin32\bin
	@true >$(NULLDEV) 2>&1
else
testenv:
	-@ true >$(NULLDEV) 2>&1 || echo Your system lacks Gnu coreutils tools !!!
	@true >$(NULLDEV) 2>&1
endif
	
clean: 
	-@ $(DELFILES) $(OBJ)/*.o
	-@ $(DELFILES) $(BIN)/stunnel.exe >$(NULLDEV) 2>&1
	-@ $(DELDIR) $(OBJ)   >$(NULLDEV) 2>&1
	-@ $(DELDIR) $(BIN)   >$(NULLDEV) 2>&1

makedirs:
	-@ $(MKDIR) $(OBJROOT) >$(NULLDEV) 2>&1
	-@ $(MKDIR) $(OBJ) >$(NULLDEV) 2>&1
	-@ $(MKDIR) $(BINROOT) >$(NULLDEV) 2>&1
	-@ $(MKDIR) $(BIN) >$(NULLDEV) 2>&1

# pseudo-target for RC-preprocessor debugging  
# result appears OK, as a text file
faketest:
	gcc -E -xc-header -DRC_INVOKED $(DEFINES) -o $(SRC)/version.rcp $(SRC)/version.rc  

# pdelaage: 4 lines not absolutely necessary with new inference rules and following dependency rule...
#$(OBJ)/resources.o: $(SRC)/resources.rc $(SRC)/resources.h $(SRC)/version.h
#$(OBJ)/version.o: $(SRC)/version.rc $(SRC)/version.h
#$(OBJ)/gui.o: $(SRC)/gui.c $(SRC)/version.h
#$(OBJ)/stunnel.o: $(SRC)/stunnel.c $(SRC)/version.h

#pdelaage THERE is NO Makefile.w32 !!! $(OBJS): *.h Makefile.w32
$(OBJS): *.h mingw.mak

$(BIN)/stunnel.exe: $(OBJS)
	$(CC) $(LDFLAGS) -o $(BIN)/stunnel.exe $(OBJS) $(LIBS) -mwindows

# TODO : 
# - version.rc in exe DOES NOT WORK with gnu-ld, ok with ms vc/evc!
# the VERSIONINFO are NOT displayed in Windows Explorer when linked by gnu-ld
# but the same OBJ file (given by windres!) linked with MS link gives proper info in Windows Explorer.
# - what to do with linux...I mean not mingw, but makefile.in/rpm...I think 
# using /obj/UNX and /bin/UNX could be a good practice.

# general comment about "missing separator" issue with mingw32-make
# tabs MUST BE TABS in your text editor, and not set of spaces
# even if your development host is windows, some \ are badly tolerated by mingw32-make
# "!" directives, eg as !IF, accepted in MS nmake and Borland make ARE NOT supported by gnu make
# but they all have equivalent.
# gnu-make is case sensitive, while ms nmake or borland make are not. Anyway, on reference to env vars
# nmake convert env vars to UPPERCASE macro names...


