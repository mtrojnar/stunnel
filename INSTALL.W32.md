# stunnel Windows install notes


### Cross-compiling 64-bit stunnel from source with MinGW (optional):

 1) Install the mingw64 cross-compiler on a Unix/Linux machine.
    On Debian (and derivatives, including Ubuntu):
      sudo apt install gcc-mingw-w64-x86-64
    On Arch Linux:
      aurman -S mingw-w64-gcc-bin

 2) Download the recent OpenSSL and unpack it:
      tar zvxf ~/openssl-(version).tar.gz
      mv openssl-(version) openssl-(version)-mingw64
      cd openssl-(version)-mingw64/

 3) Build and install OpenSSL.
      ./Configure \
        --cross-compile-prefix=x86_64-w64-mingw32- \
        --prefix=/opt/openssl-mingw64 mingw64 shared enable-capieng
      sed -i 's/"\$(OPENSSLDIR)/"..\/config/' Makefile
      sed -i 's/"\$(ENGINESDIR)/"..\/engines/' Makefile
      make
      sudo make install
      sudo cp ms/applink.c /opt/openssl-mingw64/include/openssl/

 4) Download and unpack stunnel-(version).tar.gz.

 5) Configure stunnel.
      cd stunnel-(version)
      ./configure

 6) Build 64-bit Windows executables.
      cd src
      make mingw64


### Cross-compiling 32-bit stunnel from source with MinGW (optional):

 1) Install the mingw64 cross-compiler on a Unix/Linux machine.
    On Debian (and derivatives, including Ubuntu):
      sudo apt install gcc-mingw-w64-i686
    On Arch Linux:
      aurman -S mingw-w64-gcc-bin

 2) Download the recent OpenSSL and unpack it:
      tar zvxf ~/openssl-(version).tar.gz
      mv openssl-(version) openssl-(version)-mingw
      cd openssl-(version)-mingw/

 3) Build and install OpenSSL.
      ./Configure \
        --cross-compile-prefix=i686-w64-mingw32- \
        --prefix=/opt/openssl-mingw mingw shared enable-capieng
      sed -i 's/"\$(OPENSSLDIR)/"..\/config/' Makefile
      sed -i 's/"\$(ENGINESDIR)/"..\/engines/' Makefile
      make
      sudo make install
      sudo cp ms/applink.c /opt/openssl-mingw/include/openssl/

 4) Download and unpack stunnel-(version).tar.gz.

 5) Configure stunnel.
      cd stunnel-(version)
      ./configure

 6) Build 32-bit Windows executables.
      cd src
      make mingw


### Building stunnel from source with MinGW (optional):

 Building stunnel with MinGW on a Windows machine is possible,
 but not currently supported.


### Building stunnel from source with Visual Studio (optional):

 1) Build your own or download pre-built OpenSSL library and headers.
    TODO

 2) Configure path to your OpenSSL in the src\vc.mak file.

 3) Build stunnel in Visual Studio Command Prompt.
      cd src
      nmake -f vc.mak


### Installing stunnel:

 1) Install stunnel.
    Run installer to install the precompiled binaries.
    Alternatively, copy the stunnel.exe and/or tstunnel.exe executable located in
    /stunnel-(version)/bin/mingw/ or /stunnel-(version)/bin/mingw64/ directory
    into the destination directory on a Windows machine.
    Copy OpenSSL DLLs into the same directory if necessary.
    For a MinGW build also copy libssp-0.dll.
    For a Visual Studio build also install Microsoft Visual C++ Redistributable.

 2) Read the manual (stunnel.html).

 3) Create/edit the stunnel.conf configuration file.
