Name:           stunnel
Version:        5.63
Release:        1%{?dist}
Summary:        An TLS-encrypting socket wrapper
Group:          Applications/Internet
License:        GPLv2
URL:            https://www.stunnel.org/
Source0:        https://www.stunnel.org/downloads/stunnel-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
# util-linux is needed for rename
BuildRequires:  openssl-devel, util-linux
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
BuildRequires:  systemd-units
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
%endif

%description
Stunnel is a socket wrapper which can provide TLS (Transport Layer Security) support to ordinary applications. For example, it can be used
in conjunction with imapd to create an TLS secure IMAP server.

# Do not generate provides for private libraries
%global __provides_exclude_from ^%{_libdir}/stunnel/.*$

%prep
%setup -q

%build
%configure --enable-fips --enable-ipv6 --with-ssl=%{_prefix} \
    CPPFLAGS="-UPIDFILE -DPIDFILE='\"%{_localstatedir}/run/stunnel.pid\"'"
make V=1

%install
make install DESTDIR=%{buildroot}
# Move the translated man pages to the right subdirectories, and strip off the
# language suffixes.
for lang in pl ; do
    mkdir -p %{buildroot}/%{_mandir}/${lang}/man8
    mv %{buildroot}/%{_mandir}/man8/*.${lang}.8* %{buildroot}/%{_mandir}/${lang}/man8/
    rename ".${lang}" "" %{buildroot}/%{_mandir}/${lang}/man8/*
done
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
mkdir -p %{buildroot}%{_unitdir}
cp tools/%{name}.service %{buildroot}%{_unitdir}/%{name}.service
%endif

%post
/sbin/ldconfig
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%systemd_post %{name}.service
%endif

%preun
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%systemd_preun %{name}.service
%endif

%postun
/sbin/ldconfig
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%systemd_postun_with_restart %{name}.service
%endif

%files
%{!?_licensedir:%global license %%doc}
%doc COPYING.md COPYRIGHT.md README.md NEWS.md AUTHORS.md BUGS.md CREDITS.md PORTS.md TODO.md
%license COPY*
%lang(en) %doc doc/en/*
%lang(pl) %doc doc/pl/*
%{_bindir}/stunnel
%exclude %{_bindir}/stunnel3
%exclude %{_datadir}/doc/stunnel
%{_libdir}/stunnel
%exclude %{_libdir}/stunnel/libstunnel.la
%{_mandir}/man8/stunnel.8*
%lang(pl) %{_mandir}/pl/man8/stunnel.8*
%dir %{_sysconfdir}/%{name}
%config %{_sysconfdir}/%{name}/*-sample
%exclude %{_sysconfdir}/%{name}/*.pem
%if 0%{?fedora} >= 15 || 0%{?rhel} >= 7
%{_unitdir}/%{name}*.service
%endif
%config(noreplace) %{_datarootdir}/bash-completion/*

%changelog
* Wed Mar 02 2022 Małgorzata Olszówka <Malgorzata.Olszowka@stunnel.org>
- bash completion support

* Fri Sep 24 2021 Michał Trojnara <Michal.Trojnara@stunnel.org>
- Added systemd startup for Fedora >= 15 or RHEL >= 7
- Removed obsolete init startup
- Removed obsolete logrotate configuration (replaced with journalctl)
- Removed obsolete tcp_wrappers-devel support
- Removed creating a dedicated user
- Simplified the .spec file

* Wed Apr 27 2016 Andrew Colin Kissa <andrew@topdog.za.net> - 5.32-1
- Added init script that actually works on Redhat
- Lots of changes and cleanup to improve spec

* Tue May 26 2015 Bill Quayle <Bill.Quayle@citadel.com>
- updated license specification
- the manual page is no longer marked as compressed
- removed outdated documentation files
- updated minimum required version of OpenSSL

* Fri Sep 09 2005 neeo <neeo@irc.pl>
- lots of changes and cleanups

* Wed Mar 17 2004 neeo <neeo@irc.pl>
- updated for 4.05

* Sat Jun 24 2000 Brian Hatch <bri@stunnel.org>
- updated for 3.8p3

* Wed Jul 14 1999 Dirk O. Siebnich <dok@vossnet.de>
- updated for 3.5.

* Mon Jun 07 1999 Dirk O. Siebnich <dok@vossnet.de>
- adapted from sslwrap RPM spec file
