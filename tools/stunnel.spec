Summary: Program that wraps normal socket connections with SSL/TLS
Name: stunnel
Version: 3.9
Release: 1
Copyright: GPL
Group: Applications/Networking
Source: stunnel-%{version}.tgz
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
%setup -n stunnel-%{version}


%build
if [ ! -x ./configure ]; then
    autoconf
    autoheader
fi

# !!! important settings !!!
CFLAGS="${RPM_OPT_FLAGS}" ./configure

make
make stunnel.html

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/lib
mkdir -p $RPM_BUILD_ROOT/usr/man/man8

install -m755 -s stunnel $RPM_BUILD_ROOT/usr/sbin
install -m755 -s stunnel.so $RPM_BUILD_ROOT/usr/lib
install -m644 stunnel.8 $RPM_BUILD_ROOT/usr/man/man8

%clean
rm -rf $RPM_BUILD_ROOT

%post
ldconfig

%postun
ldconfig

%files
%defattr(-,root,root)
%doc FAQ stunnel.html transproxy.txt
%doc ca.html ca.pl importCA.html importCA.sh stunnel.cnf
/usr/sbin/stunnel
/usr/lib/stunnel.so
/usr/man/man8/stunnel.8

%changelog
* Sun Jun 24 2000 Brian Hatch <bri@stunnel.org>
- updated for 3.8p3

* Wed Jul 14 1999 Dirk O. Siebnich <dok@vossnet.de>
- updated for 3.5.

* Mon Jun 07 1999 Dirk O. Siebnich <dok@vossnet.de>
- adapted from sslwrap RPM spec file

