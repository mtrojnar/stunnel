%define _prefix /usr
%define _sysconfdir /etc

Summary: Program that wraps normal socket connections with SSL/TLS
Name: stunnel
Version: 5.31
Release: 1
License: GPL with an OpenSSL exception
Group: Applications/Networking
Source: stunnel-%{version}.tar.gz
Packager: Bill Quayle <Bill.Quayle@citadel.com>
Requires: openssl >= 0.9.7
BuildRequires: openssl-devel >= 0.9.7
Buildroot: /var/tmp/stunnel-%{version}-root

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

CFLAGS="%{optflags}" ./configure --prefix=%{_prefix} --sysconfdir=%{_sysconfdir}

%{__make}

%install
%{__rm} -rf %{buildroot}
%{__mkdir} -p %{buildroot}%{_sysconfdir}/stunnel
%{__mkdir} -p %{buildroot}%{_sbindir}
%{__mkdir} -p %{buildroot}%{_libdir}
%{__mkdir} -p %{buildroot}%{_mandir}/man8
%{__mkdir} -p %{buildroot}%{_initrddir}

%{__install} -m755 -s src/stunnel %{buildroot}%{_sbindir}
%{__install} -m755 src/.libs/libstunnel.so %{buildroot}%{_libdir}
%{__install} -m755 src/.libs/libstunnel.la %{buildroot}%{_libdir}
%{__install} -m644 doc/stunnel.8 %{buildroot}%{_mandir}/man8/stunnel.8
%{__install} -m644 tools/stunnel.conf-sample %{buildroot}%{_sysconfdir}/stunnel
%{__install} -m500 tools/stunnel.init %{buildroot}%{_initrddir}/stunnel

%clean
%{__rm} -rf %{buildroot}

%post
ldconfig

%postun
ldconfig

%files
%defattr(-,root,root)
%doc COPYING COPYRIGHT.GPL README ChangeLog doc/stunnel.html
%doc tools/ca.html tools/ca.pl tools/importCA.html tools/importCA.sh tools/openssl.cnf
%dir %{_sysconfdir}/stunnel
%config %{_sysconfdir}/stunnel/*
%{_sbindir}/stunnel
%{_libdir}/libstunnel.so
%{_libdir}/libstunnel.la
%{_mandir}/man8/stunnel.8.gz
%{_initrddir}/stunnel

%changelog
* Tue May 26 2015 Bill Quayle <Bill.Quayle@citadel.com>
- updated license specification
- the manual page is no longer marked as compressed
- removed outdated documentation files
- updated minimum required version of OpenSSL

* Fri Sep 09 2005 neeo <neeo@irc.pl>
- lots of changes and cleanups

* Wed Mar 17 2004 neeo <neeo@irc.pl>
- updated for 4.05

* Sun Jun 24 2000 Brian Hatch <bri@stunnel.org>
- updated for 3.8p3

* Wed Jul 14 1999 Dirk O. Siebnich <dok@vossnet.de>
- updated for 3.5.

* Mon Jun 07 1999 Dirk O. Siebnich <dok@vossnet.de>
- adapted from sslwrap RPM spec file
