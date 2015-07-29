Summary: Program that wraps normal socket connections with SSL/TLS
Name: stunnel
Version: 3.4
Release: 1
Copyright: GPL
Group: Applications/Networking
Source: stunnel-3.3.tar.gz
Patch: stunnel-3.3-3.4.patch
Requires: openssl >= 0.9.3a
Buildroot: /var/tmp/stunnel-root

%description
The stunnel program is designed to work as SSL encryption wrapper
between remote clients and local (inetd-startable) or remote
servers. The concept is that having non-SSL aware daemons running on
your system you can easily set them up to communicate with clients over
secure SSL channels.
stunnel can be used to add SSL functionality to commonly used inetd
daemons like POP-2, POP-3, and IMAP servers, to standalone daemons like
NNTP, SMTP and HTTP, and in tunneling PPP over network sockets without
changes to the source code.
 
%prep
%setup -n stunnel-3.3
%patch -p1 -b .orig

%build
autoconf
autoheader

# !!! import settings !!!
# '-DNO_IDEA' in USA, Europe, Japan, where Ascom Systec Ltd. holds patents
# '-DNO_RSA' in USA
CFLAGS="${RPM_OPT_FLAGS} -DNO_IDEA" ./configure

make
make stunnel.html

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/man/man8
mkdir -p $RPM_BUILD_ROOT/var/openssl/certs/trusted

install -m755 -s stunnel $RPM_BUILD_ROOT/usr/sbin
install -m644 stunnel.8 $RPM_BUILD_ROOT/usr/man/man8

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc FAQ stunnel.html ca.html ca.pl importCA.html importCA.sh stunnel.cnf 
/usr/sbin/stunnel
/usr/man/man8/stunnel.8
%dir /var/openssl/certs/trusted

%changelog
* Mon Jun 07 1999 Dirk O. Siebnich <dok@vossnet.de>
- adapted from sslwrap RPM spec file

