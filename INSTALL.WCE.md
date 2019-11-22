# stunnel Windows CE install notes


### Two stunnel executables are available for Windows CE platform:

  1) stunnel.exe - version with interactive GUI

  2) tstunnel.exe - non-iteractive version for headless devices


### Building stunnel from source (optional):

  1) install the following tools:
     evt2002web_min.exe from http://www.microsoft.com/
     ActivePerl from http://www.activestate.com/Products/ActivePerl/
     unzip.exe (file needs to be renamed) from
       http://www.mirrorservice.org/sites/ftp.info-zip.org/pub/infozip/WIN32/

  2) download the OpenSSL source files (the whole directory):
     ftp://ftp.stunnel.org/stunnel/openssl/ce/
  
  3) your directory should look like this:
     build.bat
     build.pl
     unzip.exe
     src\openssl-0.9.8a.zip
     src\wcecompat-1.2.zip

  4) type "build" to build OpenSSL

  5) download and unpack stunnel-(version).tar.gz

  4) enter "stunnel-(version)\src" subdirectory

  5) type "makece" to build stunnel


### Installing stunnel:

  1) copy OpenSSL DLLs and stunnel.exe or tstunnel.exe into \stunnel directory

  2) read the manual (stunnel.html)

  3) create/edit stunnel.conf configuration file
