# vc.mak by Michal Trojnara 1998-2011
# with help of David Gillingham <dgillingham@gmail.com>
# with help of Pierre Delaage <delaage.pierre@free.fr>

# Modify this to point to your actual openssl compile directory
# (You did already compile openssl, didn't you?)
#SSLDIR=..\..\openssl-1.0.0d
SSLDIR=C:\Users\standard\Documents\Dvts\Contrib\openssl\v1.0.0c\patched3

TARGETCPU=W32
SRC=..\src
OBJROOT=..\obj
OBJ=$(OBJROOT)\$(TARGETCPU)
BINROOT=..\bin
BIN=$(BINROOT)\$(TARGETCPU)

OBJS=$(OBJ)\stunnel.obj $(OBJ)\ssl.obj $(OBJ)\ctx.obj $(OBJ)\verify.obj $(OBJ)\file.obj $(OBJ)\client.obj \
	$(OBJ)\protocol.obj $(OBJ)\sthreads.obj $(OBJ)\log.obj $(OBJ)\options.obj $(OBJ)\network.obj \
	$(OBJ)\resolver.obj $(OBJ)\gui.obj $(OBJ)\resources.res $(OBJ)\str.obj \
	$(OBJ)\version.res
	
CC=cl
DEFINES=/DUSE_WIN32 /D_CRT_SECURE_NO_DEPRECATE \
	/D_CRT_NONSTDC_NO_DEPRECATE /D_MBCS /DHOST=\"x86-pc-msvc-2008\"

CFLAGS=/MD /W3 /Ox /O2 /Ob2 /Gs0 /GF /Gy /GL /nologo \
	/I"$(SSLDIR)\inc32" $(DEFINES)

# Required for HOST symbol used in version.rc	
RFLAGS=$(DEFINES)

LINK=link
LDFLAGS=/INCREMENTAL:NO /NOLOGO /SUBSYSTEM:WINDOWS /OPT:REF \
	/OPT:ICF /LTCG /MACHINE:X86 /ERRORREPORT:PROMPT
LIBS=/LIBPATH:"$(SSLDIR)\out32dll" wsock32.lib ssleay32.lib \
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

$(BIN)\stunnel.exe: $(OBJS)
	$(LINK) $(LDFLAGS) $(LIBS) /OUT:$@ $**
	IF EXIST $@.manifest \
		mt -nologo -manifest $@.manifest -outputresource:$@;1

# end of vc.mak
