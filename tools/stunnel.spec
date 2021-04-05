Name:           stunnel
Version:        5.59
Release:        1%{?dist}
Summary:        An TLS-encrypting socket wrapper
Group:          Applications/Internet
License:        GPLv2
URL:            http://www.stunnel.org/
Source0:        https://www.stunnel.org/downloads/stunnel-%{version}.tar.gz
Source1:        %{name}.init
Source2:        %{name}.logrotate
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  openssl-devel
BuildRequires:  tcp_wrappers-devel
Requires(pre):  shadow-utils
Requires(post): chkconfig
Requires(preun): chkconfig
Requires(postun): initscripts

%description
Stunnel is a socket wrapper which can provide TLS (Transport Layer Security) support to ordinary applications. For example, it can be used
in conjunction with imapd to create an TLS secure IMAP server.

%prep
%setup -q

%build
%configure --enable-fips --enable-ipv6 --with-ssl=%{_prefix}\
     --sysconfdir=%{_sysconfdir}\
     CPPFLAGS="-UPIDFILE -DPIDFILE='\"%{_localstatedir}/lib/%{name}/%{name}.pid\"'"
make LDADD="-pie -Wl,-z,defs,-z,relro,-z,now" %{?_smp_mflags}



%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
%{__mv} $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/%{name}.conf-sample\
    $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/%{name}.conf
%{__install} -d $RPM_BUILD_ROOT%{_initrddir}
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
%{__install} -d $RPM_BUILD_ROOT%{_sysconfdir}/%{name}/conf.d
%{__install} -d $RPM_BUILD_ROOT%{_localstatedir}/log/%{name}
%{__install} -d $RPM_BUILD_ROOT%{_localstatedir}/lib/%{name}
%{__install} -p -m0755 %{SOURCE1} $RPM_BUILD_ROOT%{_initrddir}/%{name}
%{__install} -p -m0644 %{SOURCE2} $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d/%{name}
for lang in pl ; do
    mkdir -p $RPM_BUILD_ROOT/%{_mandir}/${lang}/man8
    mv $RPM_BUILD_ROOT/%{_mandir}/man8/*.${lang}.8* $RPM_BUILD_ROOT/%{_mandir}/${lang}/man8/
    rename ".${lang}" "" $RPM_BUILD_ROOT/%{_mandir}/${lang}/man8/*
done
echo "# %{name} options" > $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/%{name}

%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group %{name} >/dev/null || groupadd -f -r %{name}
if ! getent passwd %{name} >/dev/null ; then
   useradd -r -g %{name} -d %{_localstatedir}/lib/%{name} \
      -s /sbin/nologin -c "%{name} user" %{name}
fi
exit 0

%post
/sbin/ldconfig
/sbin/chkconfig --add %{name}

%postun
/sbin/ldconfig
if [ "$1" -ge "1" ] ; then
    /sbin/service %{name} restart >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%files
%defattr(-,root,root,-)
%doc COPYING.md COPYRIGHT.md README.md NEWS.md doc/stunnel.html
%doc tools/ca.html tools/ca.pl tools/importCA.html tools/importCA.sh tools/openssl.cnf
%{_bindir}/*
%{_libdir}/%{name}
%{_sysconfdir}/%{name}
%{_initrddir}/%{name}
%{_mandir}/man8/%{name}.*
%{_mandir}/pl/man8/%{name}.*
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%attr(0750,%{name},%{name}) %{_localstatedir}/lib/%{name}
%attr(0750,%{name},%{name}) %{_localstatedir}/log/%{name}

%changelog
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

* Sun Jun 24 2000 Brian Hatch <bri@stunnel.org>
- updated for 3.8p3

* Wed Jul 14 1999 Dirk O. Siebnich <dok@vossnet.de>
- updated for 3.5.

* Mon Jun 07 1999 Dirk O. Siebnich <dok@vossnet.de>
- adapted from sslwrap RPM spec file
