# vc.mak by Michal Trojnara 1998-2011
# with help of David Gillingham <dgillingham@gmail.com>
# pdelaage 20101027 : added mutlitarget support, avoiding useless recompilation or folder mess-up 
# pdelaage 20101027 : version management for Windows Explorer Property Sheet : useful to check stunnel version without starting it
# pdelaage 20101027 : winsock2 lib usage instead of winsock1. I consider this as an "historic" bug. 
# pdelaage : all this for WCE (see evc.mak) and W32

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you?)
#SSLDIR=..\..\openssl-1.0.0c
SSLDIR=C:\Users\standard\Documents\Dvts\Contrib\openssl\v1.0.0c\patched3

#pdelaage: now see version.h for a central point to VERSION management
#VERSION=4.35
# pdelaage : added a host field to be used in "Windows Explorer Property Sheet" to say :
# "this is stunnel for THIS platform".

TARGETCPU=W32
SRC=..\src
OBJROOT=..\obj
OBJ=$(OBJROOT)\$(TARGETCPU)
BINROOT=..\bin
BIN=$(BINROOT)\$(TARGETCPU)

OBJS=$(OBJ)\stunnel.obj $(OBJ)\ssl.obj $(OBJ)\ctx.obj $(OBJ)\verify.obj $(OBJ)\file.obj $(OBJ)\client.obj \
	$(OBJ)\protocol.obj $(OBJ)\sthreads.obj $(OBJ)\log.obj $(OBJ)\options.obj $(OBJ)\network.obj \
	$(OBJ)\resolver.obj $(OBJ)\gui.obj $(OBJ)\resources.res \
	$(OBJ)\version.res
	
CC=cl
DEFINES=/DUSE_WIN32 /D_CRT_SECURE_NO_DEPRECATE \
	/D_CRT_NONSTDC_NO_DEPRECATE /D_MBCS /DHOST=\"x86-pc-msvc-2008\"

#pdelaage: no more needed above /DVERSION=\"$(VERSION)\"
#pdelaage: no more needed here see version.h RFLAGS=/DVERSION=\"$(VERSION)\"

CFLAGS=/MD /W3 /Ox /O2 /Ob2 /Gs0 /GF /Gy /GL /nologo \
	/I"$(SSLDIR)\inc32" $(DEFINES)

#pdelaage: required for HOST symbol used in version.rc	
RFLAGS=$(DEFINES)

LINK=link
LDFLAGS=/INCREMENTAL:NO /NOLOGO /SUBSYSTEM:WINDOWS /OPT:REF \
	/OPT:ICF /LTCG /MACHINE:X86 /ERRORREPORT:PROMPT
#pdelaage: .lib prefix was missing for crypt32 ! ws2 is winsock2, wsock32 is winsock1 !
# we have to take ws2 !
LIBS=/LIBPATH:"$(SSLDIR)\out32dll" ws2_32.lib ssleay32.lib \
	libeay32.lib user32.lib gdi32.lib crypt32.lib shell32.lib \
	comdlg32.lib advapi32.lib

{$(SRC)\}.c{$(OBJ)\}.obj:
	$(CC) $(CFLAGS) -Fo$@ -c $<

{$(SRC)\}.cpp{$(OBJ)\}.obj:
	$(CC) $(CFLAGS) -Fo$@ -c $<
	
{$(SRC)\}.rc{$(OBJ)\}.res:
	$(RC) $(RFLAGS) -fo$@ -r $<
	
all: makedirs $(BIN)\stunnel.exe

clean:
	-@ del $(OBJS)  >NUL 2>&1
#	-@ del *.manifest >NUL 2>&1
	-@ del $(BIN)\stunnel.exe >NUL 2>&1
	-@ del $(BIN)\stunnel.exe.manifest >NUL 2>&1
	-@ rmdir $(OBJ)   >NUL 2>&1
	-@ rmdir $(BIN)   >NUL 2>&1

makedirs: 
	-@ IF NOT EXIST $(OBJROOT) mkdir $(OBJROOT) >NUL 2>&1
	-@ IF NOT EXIST $(OBJ) mkdir $(OBJ) >NUL 2>&1
	-@ IF NOT EXIST $(BINROOT) mkdir $(BINROOT) >NUL 2>&1
	-@ IF NOT EXIST $(BIN) mkdir $(BIN) >NUL 2>&1

$(OBJS): *.h vc.mak

# pdelaage added this to rebuild some things on version.h change
# NOW not absolutely necessary considering the rule above...
#	$(OBJ)\resources.res: $(SRC)\resources.rc $(SRC)\resources.h $(SRC)\version.h $(SRC)\stunnel.ico
#	   pdelaage, now useless: rc /dVERSION=\"$(VERSION)\" /fo $@ resources.rc
# $(OBJ)\version.res: $(SRC)\version.rc $(SRC)\version.h
# $(OBJ)\gui.obj: $(SRC)\gui.c $(SRC)\version.h
# $(OBJ)\stunnel.obj: $(SRC)\stunnel.c $(SRC)\version.h

$(BIN)\stunnel.exe: $(OBJS)
	$(LINK) $(LDFLAGS) $(LIBS) /OUT:$@ $**
	IF EXIST $@.manifest \
		mt -nologo -manifest $@.manifest -outputresource:$@;1

# end of vc.mak
