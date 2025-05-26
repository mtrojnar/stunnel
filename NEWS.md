# stunnel change log


### Version 5.75, 2025.05.26, urgency: MEDIUM
* Security bugfixes
  - OpenSSL DLLs updated to version 3.4.1.
  - OpenSSL FIPS Provider updated to version 3.1.2.
* Bugfixes
  - Fixed infinite loop triggered by OCSP URL parsing errors
    (thx to Richard Könning for reporting).
  - Fixed OPENSSL_NO_OCSP build issues
    (thx to Dmitry Mostovoy for reporting).
  - Fixed default curve selection in FIPS mode with OpenSSL 3.4+.
  - Fixed tests with modern Python versions.
  - Fixed tests with multiple OpenSSL versions installed.
* Features
  - Added provider URI support for "cert" and "key" options.
  - Added new "CAstore" service-level option (OpenSSL 3.0+).
  - Added "provider" (OpenSSL 3.0+), "providerParameter"
    (OpenSSL 3.5+), and "setEnv" global options.
  - Key file/URI path added to passphrase prompt on Unix.
  - PKCS#11 provider installed on Windows.

### Version 5.74, 2024.12.13, urgency: HIGH
* Bugfixes
  - Fixed a stapling cache deallocation crash.
  - Fixed "redirect" with protocol negotiation.
* Features
  - "protocolHost" support for "socks" protocol clients.
  - More detailed logs in OpenSSL 3.0 or later.

### Version 5.73, 2024.09.09, urgency: MEDIUM
* Security bugfixes
  - OpenSSL DLLs updated to version 3.3.2.
  - OpenSSL FIPS Provider updated to version 3.0.9.
* Bugfixes
  - Fixed a memory leak while reloading stunnel.conf
    sections with "client=yes" and "delay=no".
  - Fixed TIMEOUTocsp with values greater than 4.
  - Fix the IPv6 test on a non-IPv6 machine.
* Features
  - HELO replaced with EHLO in the post-STARTTLS SMTP
    protocol negotiation (thx to Peter Pentchev).
  - OCSP stapling fetches moved away from server threads.
  - Improved client-side session resumption.
  - Added support for the mimalloc allocator.
  - Check for protocolHost moved to configuration file
    processing for the client-side CONNECT protocol.
  - Clarified some confusing OpenSSL's certificate
    verification error messages.
  - stunnel.nsi updated for Debian 13 and Fedora.
  - Improved NetBSD compatibility.

### Version 5.72, 2024.02.04, urgency: MEDIUM
* Security bugfixes
  - OpenSSL DLLs updated to version 3.2.1.
* Bugfixes
  - Fixed SSL_CTX_new() errors handling.
  - Fixed OPENSSL_NO_PSK builds.
  - Android build updated for NDK r23c.
  - stunnel.nsi updated for Debian 12.
  - Fixed tests with OpenSSL older than 1.0.2.

### Version 5.71, 2023.09.19, urgency: MEDIUM
* Security bugfixes
  - OpenSSL DLLs updated to version 3.1.3.
* Bugfixes
  - Fixed the console output of tstunnel.exe.
* Features sponsored by SAE IT-systems
  - OCSP stapling is requested and verified in the client mode.
  - Using "verifyChain" automatically enables OCSP
    stapling in the client mode.
  - OCSP stapling is always available in the server mode.
  - An inconclusive OCSP verification breaks TLS negotiation.
    This can be disabled with "OCSPrequire = no".
  - Added the "TIMEOUTocsp" option to control the maximum
    time allowed for connecting an OCSP responder.
* Features
  - Added support for Red Hat OpenSSL 3.x patches.

### Version 5.70, 2023.07.12, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 3.0.9.
  - OpenSSL FIPS Provider updated to version 3.0.8.
* Bugfixes
  - Fixed TLS socket EOF handling with OpenSSL 3.x.
    This bug caused major interoperability issues between
    stunnel built with OpenSSL 3.x and Microsoft's
    Schannel Security Support Provider (SSP).
  - Fixed reading certificate chains from PKCS#12 files.
* Features
  - Added configurable delay for the "retry" option.

### Version 5.69, 2023.03.04, urgency: MEDIUM
* New features
  - Improved logging performance with the "output" option.
  - Improved file read performance on the WIN32 platform.
  - DH and kDHEPSK ciphersuites removed from FIPS defaults.
  - Set the LimitNOFILE ulimit in stunnel.service to allow
    for up to 10,000 concurrent clients.
* Bugfixes
  - Fixed the "CApath" option on the WIN32 platform by
    applying https://github.com/openssl/openssl/pull/20312.
  - Fixed stunnel.spec used for building rpm packages.
  - Fixed tests on some OSes and architectures by merging
    Debian 07-tests-errmsg.patch (thx to Peter Pentchev).

### Version 5.68, 2023.02.07, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 3.0.8.
* New features
  - Added the new 'CAengine' service-level option
    to load a trusted CA certificate from an engine.
  - Added requesting client certificates in server
    mode with 'CApath' besides 'CAfile'.
  - Improved file read performance.
  - Improved logging performance.
* Bugfixes
  - Fixed EWOULDBLOCK errors in protocol negotiation.
  - Fixed handling TLS errors in protocol negotiation.
  - Prevented following fatal TLS alerts with TCP resets.
  - Improved OpenSSL initialization on WIN32.
  - Improved testing suite stability.

### Version 5.67, 2022.11.01, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 3.0.7.
* New features
  - Provided a logging callback to custom engines.
* Bugfixes
  - Fixed "make cert" with OpenSSL older than 3.0.
  - Fixed the code and the documentation to use conscious
    language for SNI servers (thx to Clemens Lang).

### Version 5.66, 2022.09.11, urgency: MEDIUM
* New features
  - OpenSSL 3.0 FIPS Provider support for Windows.
* Bugfixes
  - Fixed building on machines without pkg-config.
  - Added the missing "environ" declaration for
    BSD-based operating systems.
  - Fixed the passphrase dialog with OpenSSL 3.0.

### Version 5.65, 2022.07.17, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 3.0.5.
* Bugfixes
  - Fixed handling globally enabled FIPS.
  - Fixed openssl.cnf processing in WIN32 GUI.
  - Fixed a number of compiler warnings.
  - Fixed tests on older versions of OpenSSL.

### Version 5.64, 2022.05.06, urgency: MEDIUM
* Security bugfixes
  - OpenSSL DLLs updated to version 3.0.3.
* New features
  - Updated the pkcs11 engine for Windows.
* Bugfixes
  - Removed the SERVICE_INTERACTIVE_PROCESS flag in
    "stunnel -install".

### Version 5.63, 2022.03.15, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 3.0.2.
* New features
  - Updated stunnel.spec to support bash completion.
* Bugfixes
  - Fixed a PRNG initialization crash (thx to Gleydson Soares).

### Version 5.62, 2022.01.17, urgency: MEDIUM
* New features
  - Added a bash completion script.
* Bugfixes
  - Fixed a transfer() loop bug.

### Version 5.61, 2021.12.22, urgency: LOW
* New features sponsored by the University of Maryland
  - Added new "protocol = capwin" and "protocol = capwinctrl"
    configuration file options.
* New features for the Windows platform
  - Added client mode allowing authenticated users to view
    logs, reconfigure and terminate running stunnel services.
  - Added support for multiple GUI and service instances
    distinguised by the location of stunnel.conf.
  - Improved log window scrolling.
  - Added a new 'Pause auto-scroll' GUI checkbox.
  - Double click on the icon tray replaced with single click.
  - OpenSSL DLLs updated to version 3.0.1.
* Other new features
  - Rewritten the testing framework in python (thx to
    Peter Pentchev for inspiration and initial framework).
  - Added support for missing SSL_set_options() values.
  - Updated stunnel.spec to support RHEL8.
* Bugfixes
  - Fixed OpenSSL 3.0 build.
  - Fixed reloading configuration with
    "systemctl reload stunnel.service".
  - Fixed incorrect messages logged for OpenSSL errors.
  - Fixed printing IPv6 socket option defaults on FreeBSD.

### Version 5.60, 2021.08.16, urgency: LOW
* New features
  - New 'sessionResume' service-level option to allow
    or disallow session resumption
  - Added support for the new SSL_set_options() values.
  - Download fresh ca-certs.pem for each new release.
* Bugfixes
  - Fixed 'redirect' with 'protocol'.  This combination is
    not supported by 'smtp', 'pop3' and 'imap' protocols.
  - Enforced minimum WIN32 log window size.
  - Fixed support for password-protected private keys with
    OpenSSL 3.0 (thx to Dmitry Belyavskiy).

### Version 5.59, 2021.04.05, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.1.1k.
* New features
  - Client-side "protocol = ldap" support (thx to Bart
    Dopheide and Seth Grover).
* Bugfixes
  - The test suite fixed not to require external connectivity.
  - Fixed paths in generated manuals (thx to Tatsuki Makino).
  - Fixed configuration reload when compression is used.
  - Fixed compilation with early releases of OpenSSL 1.1.1.

### Version 5.58, 2021.02.20, urgency: HIGH
* Security bugfixes
  - The "redirect" option was fixed to properly handle
    unauthenticated requests (thx to Martin Stein).
  - Fixed a double free with OpenSSL older than 1.1.0 (thx to
    Petr Strukov).
  - OpenSSL DLLs updated to version 1.1.1j.
* New features
  - New 'protocolHeader' service-level option to insert custom
    'connect' protocol negotiation headers.  This feature can
    be used to impersonate other software (e.g. web browsers).
  - 'protocolHost' can also be used to control the client SMTP
    protocol negotiation HELO/EHLO value.
  - Initial FIPS 3.0 support.
* Bugfixes
  - X.509v3 extensions required by modern versions of OpenSSL
    are added to generated self-signed test certificates.
  - Fixed a tiny memory leak in configuration file reload
    error handling (thx to Richard Könning).
  - Merged Debian 05-typos.patch (thx to Peter Pentchev).
  - Merged with minor changes Debian 06-hup-separate.patch
    (thx to Peter Pentchev).
  - Merged Debian 07-imap-capabilities.patch (thx to Ansgar).
  - Merged Debian 08-addrconfig-workaround.patch (thx to Peter
    Pentchev).
  - Fixed tests on the WSL2 platform.
  - NSIS installer updated to version 3.06 to fix a multiuser
    installation bug on some platforms, including 64-bit XP.
  - Fixed engine initialization (thx to Petr Strukov).
  - FIPS TLS feature is reported when a provider or container
    is available, and not when FIPS control API is available.

### Version 5.57, 2020.10.11, urgency: HIGH
* Security bugfixes
  - The "redirect" option was fixed to properly
    handle "verifyChain = yes" (thx to Rob Hoes).
  - OpenSSL DLLs updated to version 1.1.1h.
* New features
  - New securityLevel configuration file option.
  - FIPS support for RHEL-based distributions.
  - Support for modern PostgreSQL clients (thx to Bram Geron).
  - Windows tooltip texts updated to mention "stunnel".
  - TLS 1.3 configuration updated for better compatibility.
* Bugfixes
  - Fixed a transfer() loop bug.
  - Fixed memory leaks on configuration reloading errors.
  - DH/ECDH initialization restored for client sections.
  - Delay startup with systemd until network is online.
  - bin\libssp-0.dll removed when uninstalling.
  - A number of testing framework fixes and improvements.

### Version 5.56, 2019.11.22, urgency: HIGH
* New features
  - Various text files converted to Markdown format.
* Bugfixes
  - Support for realpath(3) implementations incompatible
    with POSIX.1-2008, such as 4.4BSD or Solaris.
  - Support for engines without PRNG seeding methods (thx to
    Petr Mikhalitsyn).
  - Retry unsuccessful port binding on configuration
    file reload.
  - Thread safety fixes in SSL_SESSION object handling.
  - Terminate clients on exit in the FORK threading model.

### Version 5.55, 2019.06.10, urgency: HIGH
* Security bugfixes
  - Fixed a Windows local privilege escalation vulnerability
    caused insecure OpenSSL cross-compilation defaults.
    Successful exploitation requires stunnel to be deployed
    as a Windows service, and user-writable C:\ folder. This
    vulnerability was discovered and reported by Rich Mirch.
  - OpenSSL DLLs updated to version 1.1.1c.
* Bugfixes
  - Implemented a workaround for Windows hangs caused by its
    inability to the monitor the same socket descriptor from
    multiple threads.
  - Windows configuration (including cryptographic keys)
    is now completely removed at uninstall.
  - A number of testing framework fixes and improvements.

### Version 5.54, 2019.05.15, urgency: LOW
* New features
  - New "ticketKeySecret" and "ticketMacSecret" options
    to control confidentiality and integrity protection
    of the issued session tickets.  These options allow
    for session resumption on other nodes in a cluster.
  - Added logging the list of active connections on
    SIGUSR2 or with Windows GUI.
  - Logging of the assigned bind address instead of the
    requested bind address.
* Bugfixes
  - Service threads are terminated before OpenSSL cleanup
    to prevent occasional stunnel crashes at shutdown.

### Version 5.53, 2019.04.10, urgency: HIGH
* New features
  - Android binary updated to support Android 4.x.
* Bugfixes
  - Fixed data transfer stalls introduced in stunnel 5.51.

### Version 5.52, 2019.04.08, urgency: HIGH
* Bugfixes
  - Fixed a transfer() loop bug introduced in stunnel 5.51.

### Version 5.51, 2019.04.04, urgency: MEDIUM
* New features
  - OpenSSL DLLs updated to version 1.1.1b.
  - Hexadecimal PSK keys are automatically converted to binary.
  - Session ticket support (requires OpenSSL 1.1.1 or later).
    "connect" address persistence is currently unsupported
    with session tickets.
  - SMTP HELO before authentication (thx to Jacopo Giudici).
  - New "curves" option to control the list of elliptic
    curves in OpenSSL 1.1.0 and later.
  - New "ciphersuites" option to control the list of
    permitted TLS 1.3 ciphersuites.
  - Include file name and line number in OpenSSL errors.
  - Compatibility with the current OpenSSL 3.0.0-dev branch.
  - Better performance with SSL_set_read_ahead()/SSL_pending().
* Bugfixes
  - Fixed PSKsecrets as a global option (thx to Teodor Robas).
  - Fixed a memory allocation bug (thx to matanfih).

### Version 5.50, 2018.12.02, urgency: MEDIUM
* New features
  - 32-bit Windows builds replaced with 64-bit builds.
  - OpenSSL DLLs updated to version 1.1.1.
  - Check whether "output" is not a relative file name.
  - Added sslVersion, sslVersionMin and sslVersionMax
    for OpenSSL 1.1.0 and later.
* Bugfixes
  - Fixed PSK session resumption with TLS 1.3.
  - Fixed a memory leak in the WIN32 logging subsystem.
  - Allow for zero value (ignored) TLS options.
  - Partially refactored configuration file parsing and
    logging subsystems for clearer code and minor bugfixes.
* Caveats
  - We removed FIPS support from our standard builds.
    FIPS will still be available with custom builds.

### Version 5.49, 2018.09.03, urgency: MEDIUM
* New features
  - Performance optimizations.
  - Logging of negotiated or resumed TLS session IDs (thx
    to ANSSI - National Cybersecurity Agency of France).
  - Merged Debian 10-enabled.patch and 11-killproc.patch
    (thx to Peter Pentchev).
  - OpenSSL DLLs updated to version 1.0.2p.
  - PKCS#11 engine DLL updated to version 0.4.9.
* Bugfixes
  - Fixed a crash in the session persistence implementation.
  - Fixed syslog identifier after configuration file reload.
  - Fixed non-interactive "make check" invocations.
  - Fixed reloading syslog configuration.
  - stunnel.pem created with SHA-256 instead of SHA-1.
  - SHA-256 "make check" certificates.

### Version 5.48, 2018.07.02, urgency: HIGH
* Security bugfixes
  - Fixed requesting client certificate when specified
    as a global option.
* New features
  - Certificate subject checks modified to accept certificates
    if at least one of the specified checks matches.

### Version 5.47, 2018.06.23, urgency: HIGH
* New features
  - Fast add_lock_callback for OpenSSL < 1.1.0.
    This largely improves performance on heavy load.
  - Automatic detection of Homebrew OpenSSL.
  - Clarified port binding error logs.
  - Various "make test" improvements.
* Bugfixes
  - Fixed a crash on switching to SNI secondary sections.

### Version 5.46, 2018.05.28, urgency: MEDIUM
* New features
  - The default cipher list was updated to a safer value:
    "HIGH:!aNULL:!SSLv2:!DH:!kDHEPSK".
* Bugfixes
  - Default accept address restored to INADDR_ANY.

### Version 5.45, 2018.05.21, urgency: MEDIUM
* New feature sponsored by https://loadbalancer.org/
  - Implemented delayed deallocation of service sections
    after configuration file reload.
* Other new features
  - OpenSSL DLLs updated to version 1.0.2o.
  - Deprecated the sslVersion option.
  - The "socket" option is now also available in service sections.
  - Implemented try-restart in the SysV init script (thx to
    Peter Pentchev).
  - TLS 1.3 compliant session handling for OpenSSL 1.1.1.
  - Default "failover" value changed from "rr" to "prio".
  - New "make check" tests.
* Bugfixes
  - A service no longer refuses to start if binding fails for
    some (but not all) addresses:ports.
  - Fixed compression handling with OpenSSL 1.1.0 and later.
  - _beginthread() replaced with safer _beginthreadex().
  - Fixed exception handling in libwrap.
  - Fixed exec+connect services.
  - Fixed automatic resolver delaying.
  - Fixed a Gentoo cross-compilation bug (thx to Joe Harvell).
  - A number of "make check" framework fixes.
  - Fixed false postive memory leak logs.
  - Build fixes for OpenSSL versions down to 0.9.7.
  - Fixed (again) round-robin failover in the FORK threading model.

### Version 5.44, 2017.11.26, urgency: MEDIUM
* New features
  - Signed Win32 executables, libraries, and installer.
* Bugfixes
  - Default accept address restored to INADDR_ANY.
  - Fixed a race condition in "make check".
  - Fixed removing the pid file after configuration reload.

### Version 5.43, 2017.11.05, urgency: LOW
* New features
  - OpenSSL DLLs updated to version 1.0.2m.
  - Android build updated to OpenSSL 1.1.0g.
  - Allow for multiple "accept" ports per section.
  - Self-test framework (make check).
  - Added config load before OpenSSL init (thx to Dmitrii Pichulin).
  - OpenSSL 1.1.0 support for Travis CI.
  - OpenSSL 1.1.1-dev compilation fixes.
* Bugfixes
  - Fixed a memory fault on Solaris.
  - Fixed round-robin failover in the FORK threading model.
  - Fixed handling SSL_ERROR_ZERO_RETURN in SSL_shutdown().
  - Minor fixes of the logging subsystem.

### Version 5.42, 2017.07.16, urgency: HIGH
* New features
  - "redirect" also supports "exec" and not only "connect".
  - PKCS#11 engine DLL updated to version 0.4.7.
* Bugfixes
  - Fixed premature cron thread initialization causing hangs.
  - Fixed "verifyPeer = yes" on OpenSSL <= 1.0.1.
  - Fixed pthreads support on OpenSolaris.

### Version 5.41, 2017.04.01, urgency: MEDIUM
* New features
  - PKCS#11 engine DLL updated to version 0.4.5.
  - Default engine UI set with ENGINE_CTRL_SET_USER_INTERFACE.
  - Key file name added into the passphrase console prompt.
  - Performance optimization in memory leak detection.
* Bugfixes
  - Fixed crashes with the OpenSSL 1.1.0 branch.
  - Fixed certificate verification with "verifyPeer = yes"
    and "verifyChain = no" (the default), while the peer
    only returns a single certificate.

### Version 5.40, 2017.01.28, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2k.
    https://www.openssl.org/news/secadv/20170126.txt
* New features
  - DH ciphersuites are now disabled by default.
  - The daily server DH parameter regeneration is only performed if
    DH ciphersuites are enabled in the configuration file.
  - "checkHost" and "checkEmail" were modified to require either
    "verifyChain" or "verifyPeer" (thx to Małorzata Olszówka).
* Bugfixes
  - Fixed setting default ciphers.

### Version 5.39, 2017.01.01, urgency: LOW
* New features
  - PKCS#11 engine (pkcs11.dll) added to the Win32 build.
  - Per-destination TLS session cache added for the client mode.
  - The new "logId" parameter "process" added to log PID values.
  - Added support for the new SSL_set_options() values.
  - Updated the manual page.
  - Obsolete references to "SSL" replaced with "TLS".
* Bugfixes
  - Fixed "logId" parameter to also work in inetd mode.
  - "delay = yes" properly enforces "failover = prio".
  - Fixed fd_set allocation size on Win64.
  - Fixed reloading invalid configuration file on Win32.
  - Fixed resolving addresses with unconfigured network interfaces.

### Version 5.38, 2016.11.26, urgency: MEDIUM
* New features
  - "sni=" can be used to prevent sending the SNI extension.
  - The AI_ADDRCONFIG resolver flag is used when available.
  - Merged Debian 06-lfs.patch (thx to Peter Pentchev).
* Bugfixes
  - Fixed a memory allocation bug causing crashes with OpenSSL 1.1.0.
  - Fixed error handling for mixed IPv4/IPv6 destinations.
  - Merged Debian 08-typos.patch (thx to Peter Pentchev).

### Version 5.37, 2016.11.06, urgency: MEDIUM
* Bugfixes
  - OpenSSL DLLs updated to version 1.0.2j (stops crashes).
  - The default SNI target (not handled by any secondary service)
    is handled by the primary service rather than rejected.
  - Removed thread synchronization in the FORK threading model.

### Version 5.36, 2016.09.22, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2i.
    https://www.openssl.org/news/secadv_20160922.txt
* New features
  - Added support for OpenSSL 1.1.0 built with "no-deprecated".
  - Removed direct zlib dependency.

### Version 5.35, 2016.07.18, urgency: HIGH
* Bugfixes
  - Fixed incorrectly enforced client certificate requests.
  - Only default to SO_EXCLUSIVEADDRUSE on Vista and later.
  - Fixed thread safety of the configuration file reopening.

### Version 5.34, 2016.07.05, urgency: HIGH
* Security bugfixes
  - Fixed malfunctioning "verify = 4".
* New features
  - Bind sockets with SO_EXCLUSIVEADDRUSE on WIN32.
  - Added three new service-level options: requireCert, verifyChain,
    and verifyPeer for fine-grained certificate verification control.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree.

### Version 5.33, 2016.06.23, urgency: HIGH
* New features
  - Improved memory leak detection performance and accuracy.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree.
  - SNI support also enabled on OpenSSL 0.9.8f and later (thx to
    Guillermo Rodriguez Garcia).
  - Added support for PKCS #12 (.p12/.pfx) certificates (thx to
    Dmitry Bakshaev).
* Bugfixes
  - Fixed a TLS session caching memory leak (thx to Richard Kraemer).
    Before stunnel 5.27 this leak only emerged with sessiond enabled.
  - Yet another WinCE socket fix (thx to Richard Kraemer).
  - Fixed passphrase/pin dialogs in tstunnel.exe.
  - Fixed a FORK threading build regression bug.
  - OPENSSL_NO_DH compilation fix (thx to Brian Lin).

### Version 5.32, 2016.05.03, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2h.
    https://www.openssl.org/news/secadv_20160503.txt
* New features
  - New "socket = a:IPV6_V6ONLY=yes" option to only bind IPv6.
  - Memory leak detection.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree.
  - Added/fixed Red Hat scripts (thx to Andrew Colin Kissa).
* Bugfixes
  - Workaround for a WinCE sockets quirk (thx to Richard Kraemer).
  - Fixed data alignment on 64-bit MSVC (thx to Yuris W. Auzins).

### Version 5.31, 2016.03.01, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2g.
    https://www.openssl.org/news/secadv_20160301.txt
* New features
  - Added logging the list of client CAs requested by the server.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree.
* Bugfixes
  - Only reset the watchdog if some data was actually transferred.
  - A workaround implemented for the unexpected exceptfds set by
    select() on WinCE 6.0 (thx to Richard Kraemer).
  - Fixed logging an incorrect value of the round-robin starting
    point (thx to Jose Alf.).

### Version 5.30, 2016.01.28, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2f.
    https://www.openssl.org/news/secadv_20160128.txt
* New features
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree.
  - Added OpenSSL autodetection for the recent versions of Xcode.
* Bugfixes
  - Fixed references to /etc removed from stunnel.init.in.
  - Stopped even trying -fstack-protector on unsupported platforms
    (thx to Rob Lockhart).

### Version 5.29, 2016.01.08, urgency: LOW
* New features
  - New WIN32 icons.
  - Performance improvement: rwlocks used for locking with pthreads.
* Bugfixes
  - Compilation fix for *BSD.
  - Fixed configuration file reload for relative stunnel.conf path
    on Unix.
  - Fixed ignoring CRLfile unless CAfile was also specified (thx
    to Strukov Petr).

### Version 5.28, 2015.12.11, urgency: HIGH
* New features
  - Build matrix (.travis.yml) extended with ./configure options.
  - mingw.mak updated to build tstunnel.exe (thx to Jose Alf.).
* Bugfixes
  - Fixed incomplete initialization.
  - Fixed UCONTEXT threading on OSX.
  - Fixed exit codes for information requests (as
    in "stunnel -version" or "stunnel -help").

### Version 5.27, 2015.12.03, urgency: MEDIUM
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2e.
    https://www.openssl.org/news/secadv_20151203.txt
* New features
  - Automated build testing configured with .travis.yml.
  - Added reading server certificates from hardware engines.
    For example: cert = id_45
  - Only attempt to use potentially harmful compiler or linker
    options if gcc was detected.
  - /opt/csw added to the OpenSSL directory lookup list.
  - mingw.mak updates (thx to Jose Alf.).
  - TODO list updated.

### Version 5.26, 2015.11.06, urgency: MEDIUM
* Bugfixes
  - Compilation fixes for OSX, *BSD and Solaris.

### Version 5.25, 2015.11.02, urgency: MEDIUM
* New features
  - SMTP client protocol negotiation support for
    "protocolUsername", "protocolPassword", and
    "protocolAuthentication" (thx to Douglas Harris).
  - New service-level option "config" to specify configuration
    commands introduced in OpenSSL 1.0.2 (thx to Stephen Wall).
  - The global option "foreground" now also accepts "quiet"
    parameter, which does not enable logging to stderr.
  - Manual page updated.
  - Obsolete OpenSSL engines removed from the Windows build:
    4758cca, aep, atalla, cswift, nuron, sureware.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree:
    gracefully handle symbols renamed from SSLeay* to OpenSSL*.
* Bugfixes
  - Fixed the "s_poll_wait returned 1, but no descriptor
    is ready" internal error.
  - Fixed "exec" hangs due to incorrect thread-local
    storage handling (thx to Philip Craig).
  - Fixed PRNG initialization (thx to Philip Craig).
  - Setting socket options no longer performed on PTYs.
  - Fixed 64-bit Windows build.

### Version 5.24, 2015.10.08, urgency: MEDIUM
* New features
  - Custom CRL verification was replaced with the internal
    OpenSSL functionality.
  - *BSD support for "transparent = destination" and
    client-side "protocol = socks". This feature should
    work at least on FreeBSD, OpenBSD and OS X.
  - Added a new "protocolDomain" option for the NTLM
    authentication (thx to Andreas Botsikas).
  - Improved compatibility of the NTLM phase 1 message (thx
    to Andreas Botsikas).
  - "setuid" and "setgid" options are now also available
    in service sections.  They can be used to set owner
    and group of the Unix socket specified with "accept".
  - Added support for the new OpenSSL 1.0.2 SSL options.
  - Added OPENSSL_NO_EGD support (thx to Bernard Spil).
  - VC autodetection added to makew32.bat (thx to Andreas
    Botsikas).
* Bugfixes
  - Fixed the RESOLVE [F0] TOR extension support in SOCKS5.
  - Fixed the error code reported on the failed bind()
    requests.
  - Fixed the sequential log id with the FORK threading.
  - Restored the missing Microsoft.VC90.CRT.manifest file.

### Version 5.23, 2015.09.02, urgency: LOW
* New features
  - Client-side support for the SOCKS protocol.
    See https://www.stunnel.org/socksvpn.html for details.
  - Reject SOCKS requests to connect loopback addresses.
  - New service-level option "OCSPnonce".
    The default value is "OCSPnonce = no".
  - Win32 directory structure rearranged.  The installer
    script provides automatic migration for common setups.
  - Added Win32 installer option to install stunnel for the
    current user only.  This feature does not deploy the NT
    service, but it also does not require aministrative
    privileges to install and configure stunnel.
  - stunnel.cnf was renamed to openssl.cnf in order to
    to prevent users from mixing it up with stunnel.conf.
  - Win32 desktop is automatically refreshed when the icon
    is created or removed.
  - The ca-certs.pem file is now updated on stunnel upgrade.
  - Inactive ports were removed from the PORTS file.
  - Added IPv6 support to the transparent proxy code.
* Bugfixes
  - Compilation fix for OpenSSL version older than 1.0.0.
  - Compilation fix for mingw.

### Version 5.22, 2015.07.30, urgency: HIGH
* New features
  - "OCSPaia = yes" added to the configuration file templates.
  - Improved double free detection.
* Bugfixes
  - Fixed a number of OCSP bugs.  The most severe of those
    bugs caused stunnel to treat OCSP responses that failed
    OCSP_basic_verify() checks as if they were successful.
  - Fixed the passive IPv6 resolver (broken in stunnel 5.21).

### Version 5.21, 2015.07.27, urgency: MEDIUM
* New features
  - Signal names are displayed instead of numbers.
  - First resolve IPv4 addresses on passive resolver requests.
    This speeds up stunnel startup on Win32 with a slow/defunct
    DNS service.
  - The "make check" target was modified to only build Win32
    executables when stunnel is built from a git repository (thx
    to Peter Pentchev).
  - More elaborate descriptions were added to the warning about
    using "verify = 2" without "checkHost" or "checkIP".
  - Performance optimization was performed on the debug code.
* Bugfixes
  - Fixed the FORK and UCONTEXT threading support.
  - Fixed "failover=prio" (broken since stunnel 5.15).
  - Added a retry when sleep(3) was interrupted by a signal
    in the cron thread scheduler.

### Version 5.20, 2015.07.09, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2d.
    https://www.openssl.org/news/secadv_20150709.txt
* New features
  - poll(2) re-enabled on MacOS X 10.5 and later.
  - Xcode SDK is automatically used on MacOS X if no other
    locally installed OpenSSL directory is found.
  - The SSL library detection algorithm was made a bit smarter.
  - Warnings about insecure authentication were modified to
    include the name of the affected service section.
  - A warning was added to stunnel.init if no pid file was
    specified in the configuration file (thx to Peter Pentchev).
  - Optional debugging symbols are included in the Win32 installer.
  - Documentation updates (closes Debian bug #781669).
* Bugfixes
  - Signal pipe reinitialization added to prevent turning the
    main accepting thread into a busy wait loop when an external
    condition breaks the signal pipe.  This bug was found to
    surface on Win32, but other platforms may also be affected.
  - Fixed removing the disabled taskbar icon.
  - Generated temporary DH parameters are used for configuration
    reload instead of the static defaults.
  - LSB compatibility fixes added to the stunnel.init script (thx
    to Peter Pentchev).
  - Fixed the manual page headers (thx to Gleydson Soares).

### Version 5.19, 2015.06.16, urgency: MEDIUM
* New features
  - OpenSSL DLLs updated to version 1.0.2c.
  - Added a runtime check whether COMP_zlib() method is implemented
    in order to improve compatibility with the Debian OpenSSL build.
* Bugfixes
  - Improved socket error handling.
  - Cron thread priority on Win32 platform changed to
    THREAD_PRIORITY_LOWEST to improve portability.
  - Makefile bugfixes for stunnel 5.18 regressions.
  - Fixed some typos in docs and scripts (thx to Peter Pentchev).
  - Fixed a log level check condition (thx to Peter Pentchev).

### Version 5.18, 2015.06.12, urgency: MEDIUM
* New features
  - OpenSSL DLLs updated to version 1.0.2b.
    https://www.openssl.org/news/secadv_20150611.txt
  - Added "include" configuration file option to include all
    configuration file parts located in a specified directory.
  - Log file is reopened every 24 hours.  With "log = overwrite"
    this feature can be used to prevent filling up disk space.
  - Temporary DH parameters are refreshed every 24 hours, unless
    static DH parameters were provided in the certificate file.
  - Unique initial DH parameters are distributed with each release.
  - Warnings are logged on potentially insecure authentication.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree:
    removed RLE compression support, etc.
  - Updated stunnel.spec (thx to Bill Quayle).
* Bugfixes
  - Fixed handling of dynamic connect targets.
  - Fixed handling of trailing whitespaces in the Content-Length
    header of the NTLM authentication.
  - Fixed --sysconfdir and --localstatedir handling (thx to
    Dagobert Michelsen).

### Version 5.17, 2015.04.29, urgency: HIGH
* Bugfixes
  - Fixed a NULL pointer dereference causing the service to crash.
    This bug was introduced in stunnel 5.15.

### Version 5.16, 2015.04.19, urgency: MEDIUM
* Bugfixes
  - Fixed compilation with old versions of gcc.

### Version 5.15, 2015.04.16, urgency: LOW
* New features
  - Added new service-level options "checkHost", "checkEmail" and
    "checkIP" for additional checks of the peer certificate subject.
    These options require OpenSSL version 1.0.2 or higher.
  - Win32 binary distribution now ships with the Mozilla root CA
    bundle.  This bundle is intended be used together with the new
    "checkHost" option to validate server certs accepted by Mozilla.
  - New commandline options "-reload" to reload the configuration
    file and "-reopen" to reopen the log file of stunnel running
    as a Windows service (thx to Marc McLaughlin).
  - Added session persistence based on negotiated TLS sessions.
    https://en.wikipedia.org/wiki/Load_balancing_%28computing%29#Persistence
    The current implementation does not support external TLS
    session caching with sessiond.
  - MEDIUM ciphers (currently SEED and RC4) are removed from the
    default cipher list.
  - The "redirect" option was improved to not only redirect sessions
    established with an untrusted certificate, but also sessions
    established without a client certificate.
  - OpenSSL version checking modified to distinguish FIPS and
    non-FIPS builds.
  - Improved compatibility with the current OpenSSL 1.1.0-dev tree.
  - Removed support for OpenSSL versions older than 0.9.7.
    The final update for the OpenSSL 0.9.6 branch was 17 Mar 2004.
  - "sessiond" support improved to also work in OpenSSL 0.9.7.
  - Randomize the initial value of the round-robin counter.
  - New stunnel.conf templates are provided for Windows and Unix.
* Bugfixes
  - Fixed compilation against old versions of OpenSSL.
  - Fixed memory leaks in certificate verification.

### Version 5.14, 2015.03.25, urgency: HIGH
* Security bugfixes
  - The "redirect" option now also redirects clients on SSL session
    reuse.  In stunnel versions 5.00 to 5.13 reused sessions were
    instead always connected hosts specified with the "connect"
    option regardless of their certificate verification result.
    This vulnerability was reported by Johan Olofsson.
* New features
  - Windows service is automatically restarted after upgrade.
* Bugfixes
  - Fixed a memory allocation error during Unix daemon shutdown.
  - Fixed handling multiple connect/redirect destinations.
  - OpenSSL FIPS builds are now correctly reported on startup.

### Version 5.13, 2015.03.20, urgency: MEDIUM
* New features
  - The "service" option was modified to also control the syslog
    service name.
* Bugfixes
  - Fixed Windows service crash.

### Version 5.12, 2015.03.19, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.2a.
    https://www.openssl.org/news/secadv_20150319.txt
* New features
  - New service-level option "logId" to specify the
    connection identifier type.  Currently supported types:
    "sequential" (default), "unique", and "thread".
  - New service-level option "debug" to individually control
    logging verbosity of defined services.
* Bugfixes
  - OCSP fixed on Windows platform (thx to Alec Kosky).

### Version 5.11, 2015.03.11, urgency: LOW
* New features
  - OpenSSL DLLs updated to version 1.0.2.
  - Removed dereferences of internal OpenSSL data structures.
  - PSK key lookup algorithm performance improved from
    O(N) (linear) to O(log N) (logarithmic).
* Bugfixes
  - Fixed peer certificate list in the main window on Win32
    (thx to @fyer for reporting it).
  - Fixed console logging in tstunnel.exe.
  - _tputenv_s() replaced with more portable _tputenv() on Win32.

### Version 5.10, 2015.01.22, urgency: LOW
* New features
  - OCSP AIA (Authority Information Access) support.  This feature
    can be enabled with the new service-level option "OCSPaia".
  - Additional security features of the linker are enabled:
    "-z relro", "-z now", "-z noexecstack".
* Bugfixes
  - OpenSSL DLLs updated to version 1.0.1l.
    https://www.openssl.org/news/secadv_20150108.txt
  - FIPS canister updated to version 2.0.9 in the Win32 binary
    build.

### Version 5.09, 2015.01.02, urgency: LOW
* New features
  - Added PSK authentication with two new service-level
    configuration file options "PSKsecrets" and "PSKidentity".
  - Added additional security checks to the OpenSSL memory
    management functions.
  - Added support for the OPENSSL_NO_OCSP and OPENSSL_NO_ENGINE
    OpenSSL configuration flags.
  - Added compatibility with the current OpenSSL 1.1.0-dev tree.
* Bugfixes
  - Removed defective s_poll_error() code occasionally causing
    connections to be prematurely closed (truncated).
    This bug was introduced in stunnel 4.34.
  - Fixed ./configure systemd detection (thx to Kip Walraven).
  - Fixed ./configure sysroot detection (thx to Kip Walraven).
  - Fixed compilation against old versions of OpenSSL.
  - Removed outdated French manual page.

### Version 5.08, 2014.12.09, urgency: MEDIUM
* New features
  - Added SOCKS4/SOCKS4a protocol support.
  - Added SOCKS5 protocol support.
  - Added SOCKS RESOLVE [F0] TOR extension support.
  - Updated automake to version 1.14.1.
  - OpenSSL directory searching is now relative to the sysroot.
* Bugfixes
  - Fixed improper hangup condition handling.
  - Fixed missing -pic linker option.  This is required for
    Android 5.0 and improves security.

### Version 5.07, 2014.11.01, urgency: MEDIUM
* New features
  - Several SMTP server protocol negotiation improvements.
  - Added UTF-8 byte order marks to stunnel.conf templates.
  - DH parameters are no longer generated by "make cert".
    The hardcoded DH parameters are sufficiently secure,
    and modern TLS implementations will use ECDH anyway.
  - Updated manual for the "options" configuration file option.
  - Added support for systemd 209 or later.
  - New --disable-systemd ./configure option.
  - setuid/setgid commented out in stunnel.conf-sample.
* Bugfixes
  - Added support for UTF-8 byte order mark in stunnel.conf.
  - Compilation fix for OpenSSL with disabled SSLv2 or SSLv3.
  - Non-blocking mode set on inetd and systemd descriptors.
  - shfolder.h replaced with shlobj.h for compatibility
    with modern Microsoft compilers.

### Version 5.06, 2014.10.15, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.1j.
    https://www.openssl.org/news/secadv_20141015.txt
  - The insecure SSLv2 protocol is now disabled by default.
    It can be enabled with "options = -NO_SSLv2".
  - The insecure SSLv3 protocol is now disabled by default.
    It can be enabled with "options = -NO_SSLv3".
  - Default sslVersion changed to "all" (also in FIPS mode)
    to autonegotiate the highest supported TLS version.
* New features
  - Added missing SSL options to match OpenSSL 1.0.1j.
  - New "-options" commandline option to display the list
    of supported SSL options.
* Bugfixes
  - Fixed FORK threading build regression bug.
  - Fixed missing periodic Win32 GUI log updates.

### Version 5.05, 2014.10.10, urgency: MEDIUM
* New features
  - Asynchronous communication with the GUI thread for faster
    logging on Win32.
  - systemd socket activation (thx to Mark Theunissen).
  - The parameter of "options" can now be prefixed with "-"
    to clear an SSL option, for example:
    "options = -LEGACY_SERVER_CONNECT".
  - Improved "transparent = destination" manual page (thx to
    Vadim Penzin).
* Bugfixes
  - Fixed POLLIN|POLLHUP condition handling error resulting
    in prematurely closed (truncated) connection.
  - Fixed a null pointer dereference regression bug in the
    "transparent = destination" functionality (thx to
    Vadim Penzin). This bug was introduced in stunnel 5.00.
  - Fixed startup thread synchronization with Win32 GUI.
  - Fixed erroneously closed stdin/stdout/stderr if specified
    as the -fd commandline option parameter.
  - A number of minor Win32 GUI bugfixes and improvements.
  - Merged most of the Windows CE patches (thx to Pierre Delaage).
  - Fixed incorrect CreateService() error message on Win32.
  - Implemented a workaround for defective Cygwin file
    descriptor passing breaking the libwrap support:
    http://wiki.osdev.org/Cygwin_Issues#Passing_file_descriptors

### Version 5.04, 2014.09.21, urgency: LOW
* New features
  - Support for local mode ("exec" option) on Win32.
  - Support for UTF-8 config file and log file.
  - Win32 UTF-16 build (thx to Pierre Delaage for support).
  - Support for Unicode file names on Win32.
  - A more explicit service description provided for the
    Windows SCM (thx to Pierre Delaage).
  - TCP/IP dependency added for NT service in order to prevent
    initialization failure at boot time.
  - FIPS canister updated to version 2.0.8 in the Win32 binary
    build.
* Bugfixes
  - load_icon_default() modified to return copies of default icons
    instead of the original resources to prevent the resources
    from being destroyed.
  - Partially merged Windows CE patches (thx to Pierre Delaage).
  - Fixed typos in stunnel.init.in and vc.mak.
  - Fixed incorrect memory allocation statistics update in
    str_realloc().
  - Missing REMOTE_PORT environmental variable is provided to
    processes spawned with "exec" on Unix platforms.
  - Taskbar icon is no longer disabled for NT service.
  - Fixed taskbar icon initialization when commandline options are
    specified.
  - Reportedly more compatible values used for the dwDesiredAccess
    parameter of the CreateFile() function (thx to Pierre Delaage).
  - A number of minor Win32 GUI bugfixes and improvements.

### Version 5.03, 2014.08.07, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.1i.
    See https://www.openssl.org/news/secadv_20140806.txt
* New features
  - FIPS autoconfiguration cleanup.
  - FIPS canister updated to version 2.0.6.
  - Improved SNI diagnostic logging.
* Bugfixes
  - Compilation fixes for old versions of OpenSSL.
  - Fixed whitespace handling in the stunnel.init script.

### Version 5.02, 2014.06.09, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.1h.
    See https://www.openssl.org/news/secadv_20140605.txt
* New features
  - Major rewrite of the protocol.c interface: it is now possible to add
    protocol negotiations at multiple connection phases, protocols can
    individually decide whether the remote connection will be
    established before or after SSL/TLS is negotiated.
  - Heap memory blocks are wiped before release.  This only works for
    block allocated by stunnel, and not by OpenSSL or other libraries.
  - The safe_memcmp() function implemented with execution time not
    dependent on the compared data.
  - Updated the stunnel.conf and stunnel.init templates.
  - Added a client-mode example to the manual.
* Bugfixes
  - Fixed "failover = rr" broken since version 5.00.
  - Fixed "taskbar = no" broken since version 5.00.
  - Compilation fix for missing SSL_OP_MSIE_SSLV2_RSA_PADDING option.

### Version 5.01, 2014.04.08, urgency: HIGH
* Security bugfixes
  - OpenSSL DLLs updated to version 1.0.1g.
    This version mitigates TLS heartbeat read overrun (CVE-2014-0160).
* New features
  - X.509 extensions added to the created self-signed stunnel.pem.
  - "FIPS = no" also allowed in non-FIPS builds of stunnel.
  - Search all certificates with the same subject name for a matching
    public key rather than only the first one (thx to Leon Winter).
  - Create logs in the local application data folder if stunnel folder
    is not writable on Win32.
* Bugfixes
  - close_notify not sent when SSL still has some data buffered.
  - Protocol negotiation with server-side SNI fixed.
  - A Mac OS X missing symbols fixed.
  - Win32 configuration file reload crash fixed.
  - Added s_pool_free() on exec+connect service retires.
  - Line-buffering enforced on stderr output.

### stunnel 5.00 disables some features previously enabled by default.
### Users should review whether the new defaults are appropriate for their
### particular deployments.  Packages maintainers may consider prepending
### the old defaults for "fips" (if supported by their OpenSSL library),
### "pid" and "libwrap" to stunnel.conf during automated updates.

### Version 5.00, 2014.03.06, urgency: HIGH
* Security bugfixes
  - Added PRNG state update in fork threading (CVE-2014-0016).
* New global configuration file defaults
  - Default "fips" option value is now "no", as FIPS mode is only
    helpful for compliance, and never for actual security.
  - Default "pid" is now "", i.e. not to create a pid file at startup.
* New service-level configuration file defaults
  - Default "ciphers" updated to "HIGH:MEDIUM:+3DES:+DH:!aNULL:!SSLv2"
    due to AlFBPPS attack and bad performance of DH ciphersuites.
  - Default "libwrap" setting is now "no" to improve performance.
* New features
  - OpenSSL DLLs updated to version 1.0.1f.
  - zlib DLL updated to version 1.2.8.
  - autoconf scripts upgraded to version 2.69.
  - TLS 1.1 and TLS 1.2 are now allowed in the FIPS mode.
  - New service-level option "redirect" to redirect SSL client
    connections on authentication failures instead of rejecting them.
  - New global "engineDefault" configuration file option to control
    which OpenSSL tasks are delegated to the current engine.
    Available tasks: ALL, RSA, DSA, ECDH, ECDSA, DH, RAND, CIPHERS,
    DIGESTS, PKEY, PKEY_CRYPTO, PKEY_ASN1.
  - New service-level configuration file option "engineId" to select
    the engine by identifier, e.g. "engineId = capi".
  - New global configuration file option "log" to control whether to
    append (the default), or to overwrite log file while (re)opening.
  - Different taskbar icon colors to indicate the service state.
  - New global configuration file options "iconIdle", "iconActive",
    and "iconError" to select status icon on GUI taskbar.
  - Removed the limit of 63 stunnel.conf sections on Win32 platform.
  - Installation of a sample certificate was moved to a separate "cert"
    target in order to allow unattended (e.g. scripted) installations.
  - Reduced length of the logged thread identifier.  It is still based
    on the OS thread ID, and thus not unique over long periods of time.
  - Improved readability of error messages printed when stunnel refuses
    to start due to a critical error.
* Bugfixes
  - LD_PRELOAD Solaris compatibility bug fixed (thx to Norm Jacobs).
  - CRYPTO_NUM_LOCKS replaced with CRYPTO_num_locks() to improve binary
    compatibility with diverse builds of OpenSSL (thx to Norm Jacobs).
  - Corrected round-robin failover behavior under heavy load.
  - Numerous fixes in the engine support code.
  - On Win32 platform .rnd file moved from c:\ to the stunnel folder.

### Version 4.57, 2015.04.01, urgency: HIGH
* Security bugfixes
  - Added PRNG state update in fork threading (CVE-2014-0016).

### Version 4.56, 2013.03.22, urgency: HIGH
* New features
  - Win32 installer automatically configures firewall exceptions.
  - Win32 installer configures administrative shortcuts to invoke UAC.
  - Improved Win32 GUI shutdown time.
* Bugfixes
  - Fixed a regression bug introduced in version 4.55 causing random
    crashes on several platforms, including Windows 7.
  - Fixed startup crashes on some Win32 systems.
  - Fixed incorrect "stunnel -exit" process synchronisation.
  - Fixed FIPS detection with new versions of the OpenSSL library.
  - Failure to open the log file at startup is no longer ignored.

### Version 4.55, 2013.03.03, urgency: HIGH
* Security bugfixes
  - Buffer overflow vulnerability fixed in the NTLM authentication
    of the CONNECT protocol negotiation.
    See https://www.stunnel.org/CVE-2013-1762.html for details.
  - OpenSSL updated to version 1.0.1e in Win32/Android builds.
* New features
  - SNI wildcard matching in server mode.
  - Terminal version of stunnel (tstunnel.exe) build for Win32.
* Bugfixes
  - Fixed write half-close handling in the transfer() function (thx to
    Dustin Lundquist).
  - Fixed EAGAIN error handling in the transfer() function (thx to Jan Bee).
  - Restored default signal handlers before execvp() (thx to Michael Weiser).
  - Fixed memory leaks in protocol negotiation (thx to Arthur Mesh).
  - Fixed a file descriptor leak during configuration file reload (thx to
    Arthur Mesh).
  - Closed SSL sockets were removed from the transfer() c->fds poll.
  - Minor fix in handling exotic inetd-mode configurations.
  - WCE compilation fixes.
  - IPv6 compilation fix in protocol.c.
  - Windows installer fixes.

### Version 4.54, 2012.10.09, urgency: MEDIUM
* New Win32 features
  - FIPS module updated to version 2.0.
  - OpenSSL DLLs updated to version 1.0.1c.
  - zlib DLL updated to version 1.2.7.
  - Engine DLLs added: 4758cca, aep, atalla, capi, chil, cswift, gmp, gost,
    nuron, padlock, sureware, ubsec.
* Other new features
  - "session" option renamed to more readable "sessionCacheTimeout".
    The old name remains accepted for backward compatibility.
  - New service-level "sessionCacheSize" option to control session cache size.
  - New service-level option "reset" to control whether TCP RST flag is used
    to indicate errors.  The default value is "reset = yes".
  - New service-level option "renegotiation" to disable SSL renegotiation.
    This feature is based on a public-domain patch by Janusz Dziemidowicz.
  - New FreeBSD socket options: IP_FREEBIND, IP_BINDANY, IPV6_BINDANY (thx
    to Janusz Dziemidowicz).
  - New parameters to configure TLS v1.1/v1.2 with OpenSSL version 1.0.1
    or higher (thx to Henrik Riomar).
* Bugfixes
  - Fixed "Application Failed to Initialize Properly (0xc0150002)" error.
  - Fixed missing SSL state debug log entries.
  - Fixed a race condition in libwrap code resulting in random stalls (thx
    to Andrew Skalski).
  - Session cache purged at configuration file reload to reduce memory leak.
    Remaining leak of a few kilobytes per section is yet to be fixed.
  - Fixed a regression bug in "transparent = destination" functionality (thx
    to Stefan Lauterbach). This bug was introduced in stunnel 4.51.
  - "transparent = destination" is now a valid endpoint in inetd mode.
  - "delay = yes" fixed to work even if specified *after* "connect" option.
  - Multiple "connect" targets fixed to also work with delayed resolver.
  - The number of resolver retries of EAI_AGAIN error has been limited to 3
    in order to prevent infinite loops.

### Version 4.53, 2012.03.19, urgency: MEDIUM
* New features
  - Added client-mode "sni" option to directly control the value of
    TLS Server Name Indication (RFC 3546) extension.
  - Added support for IP_FREEBIND socket option with a pached Linux kernel.
  - Glibc-specific dynamic allocation tuning was applied to help unused memory
    deallocation.
  - Non-blocking OCSP implementation.
* Bugfixes
  - Compilation fixes for old versions of OpenSSL (tested against 0.9.6).
  - Usage of uninitialized variables fixed in exec+connect services.
  - Occasional logging subsystem crash with exec+connect services.
  - OpenBSD compilation fix (thx to Michele Orru').
  - Session id context initialized with session name rather than a constant.
  - Fixed handling of a rare inetd mode use case, where either stdin or stdout
    is a socket, but not both of them at the same time.
  - Fixed missing OPENSSL_Applink http://www.openssl.org/support/faq.html#PROG2
  - Fixed crash on termination with FORK threading model.
  - Fixed dead canary after configuration reload with open connections.
  - Fixed missing file descriptors passed to local mode processes.
  - Fixed required jmp_buf alignment on Itanium platform.
  - Removed creating /dev/zero in the chroot jail on Solaris platform.
  - Fixed detection of WSAECONNREFUSED Winsock error.
  - Missing Microsoft.VC90.CRT.manifest added to Windows installer.

### Version 4.52, 2012.01.12, urgency: MEDIUM
* Bugfixes
  - Fixed write closure notification for non-socket file descriptors.
  - Removed a line logged to stderr in inetd mode.
  - Fixed "Socket operation on non-socket" error in inetd mode on Mac OS X
    platform.
  - Removed direct access to the fields of the X509_STORE_CTX data structure.

### Version 4.51, 2012.01.09, urgency: MEDIUM
* New features
  - Updated Win32 binary distribution OpenSSL DLLs to version 0.9.8s-fips.
  - Updated Android binary OpenSSL to version 1.0.0f.
  - Zlib support added to Win32 and Android binary builds.
  - New "compression = deflate" global option to enable RFC 2246 compresion.
    For compatibility with previous versions "compression = zlib" and
    "compression = rle" also enable the deflate (RFC 2246) compression.
  - Compression is disabled by default.
  - Separate default ciphers and sslVersion for "fips = yes" and "fips = no".
  - UAC support for editing configuration file with Windows GUI.
* Bugfixes
  - Fixed exec+connect sections.
  - Added a workaround for broken Android getaddrinfo():
    http://stackoverflow.com/questions/7818246/segmentation-fault-in-getaddrinfo

### Version 4.50, 2011.12.03, urgency: MEDIUM
* New features
  - Added Android port.
  - Updated INSTALL.FIPS.
* Bugfixes
  - Fixed internal memory allocation problem in inetd mode.
  - Fixed FIPS mode on Microsoft Vista, Server 2008, and Windows 7.
    This fix required to compile OpenSSL FIPS-compliant DLLs with MSVC 9.0,
    instead of MSVC 10.0.  msvcr100.dll was replaced with msvcr90.dll.
    GPL compatibility issues are explained in the GPL FAQ:
    http://www.gnu.org/licenses/gpl-faq.html#WindowsRuntimeAndGPL
  - POP3 server-side protocol negotiation updated to report STLS
    capability (thx to Anthony Morgan).

### Version 4.49, 2011.11.28, urgency: MEDIUM
* Bugfixes
  - Missing Microsoft Visual C++ Redistributable (msvcr100.dll) required
    by FIPS-compliant OpenSSL library was added to the Windows installer.
  - A bug was fixed causing crashes on MacOS X and some other platforms.

### Version 4.48, 2011.11.26, urgency: MEDIUM
* New features
  - FIPS support on Win32 platform added.  OpenSSL 0.9.8r DLLs based on
    FIPS 1.2.3 canister are included with this version of stunnel.  FIPS
    mode can be disabled with "fips = no" configuration file option.
* Bugfixes
  - Fixed canary initialization problem on Win32 platform.

### Version 4.47, 2011.11.21, urgency: MEDIUM
* Internal improvements
  - CVE-2010-3864 workaround improved to check runtime version of OpenSSL
    rather than compiled version, and to allow OpenSSL 0.x.x >= 0.9.8p.
  - Encoding of man page sources changed to UTF-8.
* Bugfixes
  - Handling of socket/SSL close in transfer() function was fixed.
  - Logging was modified to save and restore system error codes.
  - Option "service" was restricted to Unix, as since stunnel 4.42 it
    wasn't doing anything useful on Windows platform.

### Version 4.46, 2011.11.04, urgency: LOW
* New features
  - Added Unix socket support (e.g. "connect = /var/run/stunnel/socket").
  - Added "verify = 4" mode to ignore CA chain and only verify peer certificate.
  - Removed the limit of 16 IP addresses for a single 'connect' option.
  - Removed the limit of 256 stunnel.conf sections in PTHREAD threading model.
    It is still not possible have more than 63 sections on Win32 platform.
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms740141(v=vs.85).aspx
* Optimizations
  - Reduced per-connection memory usage.
  - Performed a major refactoring of internal data structures.  Extensive
    internal testing was performed, but some regression bugs are expected.
* Bugfixes
  - Fixed Win32 compilation with Mingw32.
  - Fixed non-blocking API emulation layer in UCONTEXT threading model.
  - Fixed signal handling in UCONTEXT threading model.

### Version 4.45, 2011.10.24, urgency: LOW
* New features
  - "protocol = proxy" support to send original client IP address to haproxy:
    http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
    This requires accept-proxy bind option of haproxy 1.5-dev3 or later.
  - Added Win32 configuration reload without a valid configuration loaded.
  - Added compatibility with LTS OpenSSL versions 0.9.6 and 0.9.7.
    Some features are only available in OpenSSL 1.0.0 and later.
* Performance optimizations
  - Use SSL_MODE_RELEASE_BUFFERS if supported by the OpenSSL library.
  - Libwrap helper processes are no longer started if libwrap is disabled
    in all sections of the configuration file.
* Internal improvements
  - Protocol negotiation framework was rewritten to support additional
    code to be executed after SSL_accept()/SSL_connect().
  - Handling of memory allocation errors was rewritten to gracefully
    terminate the process (thx to regenrecht for the idea).
* Bugfixes
  - Fixed -l option handling in stunnel3 script (thx to Kai Gülzau).
  - Script to build default stunnel.pem was fixed (thx to Sebastian Kayser).
  - MinGW compilation script (mingw.mak) was fixed (thx to Jose Alf).
  - MSVC compilation script (vc.mak) was fixed.
  - A number of problems in WINSOCK error handling were fixed.

### Version 4.44, 2011.09.17, urgency: MEDIUM
* New features
  - Major automake/autoconf cleanup.
  - Heap buffer overflow protection with canaries.
  - Stack buffer overflow protection with -fstack-protector.
* Bugfixes
  - Fixed garbled error messages on errors with setuid/setgid options.
  - SNI fixes (thx to Alexey Drozdov).
  - Use after free in fdprintf() (thx to Alexey Drozdov).
    This issue might cause GPF with "protocol" or "ident" options.

### Version 4.43, 2011.09.07, urgency: MEDIUM
* New features
  - Updated Win32 DLLs for OpenSSL 1.0.0e.
  - Major optimization of the logging subsystem.
    Benchmarks indicate up to 15% stunnel performance improvement.
* Bugfixes
  - Fixed Win32 configuration file reload.
  - Fixed FORK and UCONTEXT threading models.
  - Corrected INSTALL.W32 file.

### Version 4.42, 2011.08.18, urgency: HIGH
* New features
  - New verify level 0 to request and ignore peer certificate.  This
    feature is useful with the new Windows GUI menu to save cached peer
    certificate chains, as SSL client certificates are not sent by default.
  - Manual page has been updated.
  - Removed support for changing Windows Service name with "service" option.
* Bugfixes
  - Fixed a heap corruption vulnerability in versions 4.40 and 4.41.  It may
    possibly be leveraged to perform DoS or remote code execution attacks.
  - The -quiet commandline option was applied to *all* message boxes.
  - Silent install (/S option) no longer attempts to create stunnel.pem.

### Version 4.41, 2011.07.25, urgency: MEDIUM
* Bugfixes
  - Fixed Windows service crash of stunnel 4.40.

### Version 4.40, 2011.07.23, urgency: LOW
* New Win32 features
  - Added a GUI menu to save cached peer certificate chains.
  - Added comandline "-exit" option to stop stunnel *not* running
    as a service.  This option may be useful for scripts.
  - Added file version information to stunnel.exe.
  - A number of other GUI improvements.
* Other new features
  - Hardcoded 2048-bit DH parameters are used as a fallback if DH parameters
    are not provided in stunnel.pem.
  - Default "ciphers" value updated to prefer ECDH:
    "ALL:!SSLv2:!aNULL:!EXP:!LOW:-MEDIUM:RC4:+HIGH".
  - Default ECDH curve updated to "prime256v1".
  - Removed support for temporary RSA keys (used in obsolete export ciphers).

### Version 4.39, 2011.07.06, urgency: LOW
* New features
  - New Win32 installer module to build self-signed stunnel.pem.
  - Added configuration file editing with Windows GUI.
  - Added log file reopening file editing with Windows GUI.
    It might be useful to also implement log file rotation.
  - Improved configuration file reload with Windows GUI.

### Version 4.38, 2011.06.28, urgency: MEDIUM
* New features
  - Server-side SNI implemented (RFC 3546 section 3.1) with a new
    service-level option "nsi".
  - "socket" option also accepts "yes" and "no" for flags.
  - Nagle's algorithm is now disabled by default for improved interactivity.
* Bugfixes
  - A compilation fix was added for OpenSSL version < 1.0.0.
  - Signal pipe set to non-blocking mode.  This bug caused hangs of stunnel
    features based on signals, e.g. local mode, FORK threading, or
    configuration file reload on Unix.  Win32 platform was not affected.

### Version 4.37, 2011.06.17, urgency: MEDIUM
* New features
  - Client-side SNI implemented (RFC 3546 section 3.1).
  - Default "ciphers" changed from the OpenSSL default to a more secure
    and faster "RC4-MD5:HIGH:!aNULL:!SSLv2".
    A paranoid (and usually slower) setting would be "HIGH:!aNULL:!SSLv2".
  - Recommended "options = NO_SSLv2" added to the sample stunnel.conf file.
  - Default client method upgraded from SSLv3 to TLSv1.
    To connect servers without TLS support use "sslVersion = SSLv3" option.
  - Improved --enable-fips and --disable-fips ./configure option handling.
  - On startup stunnel now compares the compiled version of OpenSSL against
    the running version of OpenSSL. A warning is logged on mismatch.
* Bugfixes
  - Non-blocking socket handling in local mode fixed (Debian bug #626856).
  - UCONTEXT threading mode fixed.
  - Removed the use of gcc Thread-Local Storage for improved portability.
  - va_copy macro defined for platforms that do not have it.
  - Fixed "local" option parsing on IPv4 systems.
  - Solaris compilation fix (redefinition of "STR").

### Version 4.36, 2011.05.03, urgency: LOW
* New features
  - Updated Win32 DLLs for OpenSSL 1.0.0d.
  - Dynamic memory management for strings manipulation:
    no more static STRLEN limit, lower stack footprint.
  - Strict public key comparison added for "verify = 3" certificate
    checking mode (thx to Philipp Hartwig).
  - Backlog parameter of listen(2) changed from 5 to SOMAXCONN:
    improved behavior on heavy load.
  - Example tools/stunnel.service file added for systemd service manager.
* Bugfixes
  - Missing pthread_attr_destroy() added to fix memory leak (thx to
    Paul Allex and Peter Pentchev).
  - Fixed the incorrect way of setting FD_CLOEXEC flag.
  - Fixed --enable-libwrap option of ./configure script.
  - /opt/local added to OpenSSL search path for MacPorts compatibility.
  - Workaround implemented for signal handling on MacOS X.
  - A trivial bug fixed in the stunnel.init script.
  - Retry implemented on EAI_AGAIN error returned by resolver calls.

### Version 4.35, 2011.02.05, urgency: LOW
* New features
  - Updated Win32 DLLs for OpenSSL 1.0.0c.
  - Transparent source (non-local bind) added for FreeBSD 8.x.
  - Transparent destination ("transparent = destination") added for Linux.
* Bugfixes
  - Fixed reload of FIPS-enabled stunnel.
  - Compiler options are now auto-detected by ./configure script
    in order to support obsolete versions of gcc.
  - Async-signal-unsafe s_log() removed from SIGTERM/SIGQUIT/SIGINT handler.
  - CLOEXEC file descriptor leaks fixed on Linux >= 2.6.28 with glibc >= 2.10.
    Irreparable race condition leaks remain on other Unix platforms.
    This issue may have security implications on some deployments:
    http://udrepper.livejournal.com/20407.html
  - Directory lib64 included in the OpenSSL library search path.
  - Windows CE compilation fixes (thx to Pierre Delaage).
  - Deprecated RSA_generate_key() replaced with RSA_generate_key_ex().
* Domain name changes (courtesy of Bri Hatch)
  - http://stunnel.mirt.net/ --> http://www.stunnel.org/
  - ftp://stunnel.mirt.net/ --> http://ftp.stunnel.org/
  - stunnel.mirt.net::stunnel --> rsync.stunnel.org::stunnel
  - stunnel-users@mirt.net --> stunnel-users@stunnel.org
  - stunnel-announce@mirt.net --> stunnel-announce@stunnel.org

### Version 4.34, 2010.09.19, urgency: LOW
* New features
  - Updated Win32 DLLs for OpenSSL 1.0.0a.
  - Updated Win32 DLLs for zlib 1.2.5.
  - Updated automake to version 1.11.1
  - Updated libtool to version 2.2.6b
  - Added ECC support with a new service-level "curve" option.
  - DH support is now enabled by default.
  - Added support for OpenSSL builds with some algorithms disabled.
  - ./configure modified to support cross-compilation.
  - Sample stunnel.init updated based on Debian init script.
* Bugfixes
  - Implemented fixes in user interface to enter engine PIN.
  - Fixed a transfer() loop issue on socket errors.
  - Fixed missing Win32 taskbar icon while displaying a global option error.

### Version 4.33, 2010.04.05, urgency: MEDIUM
* New features
  - Win32 DLLs for OpenSSL 1.0.0.
    This library requires to c_rehash CApath/CRLpath directories on upgrade.
  - Win32 DLLs for zlib 1.2.4.
  - Experimental support for local mode on Win32 platform.
    Try "exec = c:\windows\system32\cmd.exe".
* Bugfixes
  - Inetd mode fixed.

### Version 4.32, 2010.03.24, urgency: MEDIUM
* New features
  - New service-level "libwrap" option for run-time control whether
    /etc/hosts.allow and /etc/hosts.deny are used for access control.
    Disabling libwrap significantly increases performance of stunnel.
  - Win32 DLLs for OpenSSL 0.9.8m.
* Bugfixes
  - Fixed a transfer() loop issue with SSLv2 connections.
  - Fixed a "setsockopt IP_TRANSPARENT" warning with "local" option.
  - Logging subsystem bugfixes and cleanup.
  - Installer bugfixes for Vista and later versions of Windows.
  - FIPS mode can be enabled/disabled at runtime.

### Version 4.31, 2010.02.03, urgency: MEDIUM
* New features
  - Log file reopen on USR1 signal was added.
* Bugfixes
  - Some regression issues introduced in 4.30 were fixed.

### Version 4.30, 2010.01.21, urgency: LOW/EXPERIMENTAL
* New features
  - Graceful configuration reload with HUP signal on Unix
    and with GUI on Windows.

### Version 4.29, 2009.12.02, urgency: MEDIUM
* New feature sponsored by Searchtech Limited http://www.astraweb.com/
  - sessiond, a high performance SSL session cache was built for stunnel.
    A new service-level "sessiond" option was added.  sessiond is
    available for download on ftp://ftp.stunnel.org/stunnel/sessiond/ .
    stunnel clusters will be a lot faster, now!
* Bugfixes
  - "execargs" defaults to the "exec" parameter (thx to Peter Pentchev).
  - Compilation fixes added for AIX and old versions of OpenSSL.
  - Missing "fips" option was added to the manual.

### Version 4.28, 2009.11.08, urgency: MEDIUM
* New features
  - Win32 DLLs for OpenSSL 0.9.8l.
  - Transparent proxy support on Linux kernels >=2.6.28.
    See the manual for details.
  - New socket options to control TCP keepalive on Linux:
    TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL.
  - SSL options updated for the recent version of OpenSSL library.
* Bugfixes
  - A serious bug in asynchronous shutdown code fixed.
  - Data alignment updated in libwrap.c.
  - Polish manual encoding fixed.
  - Notes on compression implementation in OpenSSL added to the manual.

### Version 4.27, 2009.04.16, urgency: MEDIUM
* New features
  - Win32 DLLs for OpenSSL 0.9.8k.
  - FIPS support was updated for openssl-fips 1.2.
  - New priority failover strategy for multiple "connect" targets,
    controlled with "failover=rr" (default) or "failover=prio".
  - pgsql protocol negotiation by Marko Kreen <markokr@gmail.com>.
  - Building instructions were updated in INSTALL.W32 file.
* Bugfixes
  - Libwrap helper processes fixed to close standard
    input/output/error file descriptors.
  - OS2 compilation fixes.
  - WCE fixes by Pierre Delaage <delaage.pierre@free.fr>.

### Version 4.26, 2008.09.20, urgency: MEDIUM
* New features
  - Win32 DLLs for OpenSSL 0.9.8i.
  - /etc/hosts.allow and /etc/hosts.deny no longer need to be
    copied to the chrooted directory, as the libwrap processes
    are no longer chrooted.
  - A more informative error messages for invalid port number
    specified in stunnel.conf file.
  - Support for Microsoft Visual C++ 9.0 Express Edition.
* Bugfixes
  - Killing all libwrap processes at stunnel shutdown fixed.
  - A minor bug in stunnel.init sample SysV startup file fixed.

### Version 4.25, 2008.06.01, urgency: MEDIUM
* New features
  - Win32 DLLs for OpenSSL 0.9.8h.
* Bugfixes
  - Spawning libwrap processes delayed until privileges are dropped.
  - Compilation fix for systems without struct msghdr.msg_control.

### Version 4.24, 2008.05.19, urgency: HIGH
* Bugfixes
  - OCSP code was fixed to properly reject revoked certificates.

### Version 4.23, 2008.05.03, urgency: HIGH
* Bugfixes
  - Local privilege escalation bug on Windows NT based
    systems fixed.  A local user could exploit stunnel
    running as a service to gain localsystem privileges.

### Version 4.22, 2008.03.28, urgency: MEDIUM
* New features
  - Makefile was updated to use standard autoconf variables:
    sysconfdir, localstatedir and pkglibdir.
  - A new global option to control logging to syslog:
      syslog = yes|no
    Simultaneous logging to a file and the syslog is now possible.
  - A new service-level option to control stack size:
      stack = <number of bytes>
* Bugfixes
  - Restored chroot() to be executed after decoding numerical
    userid and groupid values in drop_privileges().
  - A few bugs fixed the in the new libwrap support code.
  - TLSv1 method used by default in FIPS mode instead of
    SSLv3 client and SSLv23 server methods.
  - OpenSSL GPL license exception update based on
    http://www.gnu.org/licenses/gpl-faq.html#GPLIncompatibleLibs

### Version 4.21, 2007.10.27, urgency: LOW/EXPERIMENTAL
* New features sponsored by Open-Source Software Institute
  - Initial FIPS 140-2 support (see INSTALL.FIPS for details).
    Win32 platform is not currently supported.
* New features
  - Experimental fast support for non-MT-safe libwrap is provided
    with pre-spawned processes.
  - Stunnel binary moved from /usr/local/sbin to /usr/local/bin
    in order to meet FHS and LSB requirements.
    Please delete the /usr/local/sbin/stunnel when upgrading.
  - Added code to disallow compiling stunnel with pthreads when
    OpenSSL is compiled without threads support.
  - Win32 DLLs for OpenSSL 0.9.8g.
  - Minor manual update.
  - TODO file updated.
* Bugfixes
  - Dynamic locking callbacks added (needed by some engines to work).
  - AC_ARG_ENABLE fixed in configure.am to accept yes/no arguments.
  - On some systems libwrap requires yp_get_default_domain from libnsl,
    additional checking for libnsl was added to the ./configure script.
  - Sending a list of trusted CAs for the client to choose the right
    certificate restored.
  - Some compatibility issues with NTLM authentication fixed.
  - Taskbar icon (unless there is a config file parsing error) and
    "Save As" disabled in the service mode for local Win32 security
    (it's much like Yeti -- some people claim they have seen it).

### Version 4.20, 2006.11.30, urgency: MEDIUM
* Release notes
  - The new transfer() function has been well tested.
    I recommend upgrading any previous version with this one.
* Bugfixes
  - Fixed support for encrypted passphrases on Unix (broken in 4.19).
  - Reduced amount of debug logs.
  - A minor man page update.

### Version 4.19, 2006.11.11, urgency: LOW/EXPERIMENTAL
* Release notes
  - There are a lot of new features in this version.  I recommend
    to test it well before upgrading your mission-critical systems.
* New features
  - New service-level option to specify an OCSP responder flag:
    OCSPflag = <flag>
  - "protocolCredentials" option changed to "protocolUsername"
    and "protocolPassword"
  - NTLM support to be enabled with the new service-level option:
    protocolAuthentication = NTLM
  - imap protocol negotiation support added.
  - Passphrase cache was added so the user does not need to reenter
    the same passphrase for each defined service any more.
  - New service-level option to retry exec+connect section:
    retry = yes|no
  - Local IP and port is logged for each established connection.
  - Win32 DLLs for OpenSSL 0.9.8d.
* Bugfixes
  - Serious problem with SSL_WANT_* retries fixed.
    The new code requires extensive testing!

### Version 4.18, 2006.09.26, urgency: MEDIUM
* Bugfixes
  - GPF on entering private key pass phrase on Win32 fixed.
  - Updated OpenSSL Win32 DLLs.
  - Minor configure script update.

### Version 4.17, 2006.09.10, urgency: MEDIUM
* New features
  - Win32 DLLs for OpenSSL 0.9.8c.
* Bugfixes
  - Problem with detecting getaddrinfo() in ./configure fixed.
  - Compilation problem due to misplaced #endif in ssl.c fixed.
  - Duplicate 220 in smtp_server() function in protocol.c fixed.
  - Minor os2.mak update.
  - Minor update of safestring()/safename() macros.

### Version 4.16, 2006.08.31, urgency: MEDIUM
* New features sponsored by Hewlett-Packard
  - A new global option to control engine:
    engineCtrl = <command>[:<parameter>]
  - A new service-level option to select engine to read private key:
    engineNum = <engine number>
  - OCSP support:
    ocsp = <URL>
* New features
  - A new option to select version of SSL protocol:
    sslVersion = all|SSLv2|SSLv3|TLSv1
  - Visual Studio vc.mak by David Gillingham <dgillingham@gmail.com>.
  - OS2 support by Paul Smedley (http://smedley.info)
* Bugfixes
  - An ordinary user can install stunnel again.
  - Compilation problem with --enable-dh fixed.
  - Some minor compilation warnings fixed.
  - Service-level CRL cert store implemented.
  - GPF on protocol negotiations fixed.
  - Problem detecting addrinfo() on Tru64 fixed.
  - Default group is now detected by configure script.
  - Check for maximum number of defined services added.
  - OpenSSL_add_all_algorithms() added to SSL initialization.
  - configure script sections reordered to detect pthread library functions.
  - RFC 2487 autodetection improved.  High resolution s_poll_wait()
    not currently supported by UCONTEXT threading.
  - More precise description of cert directory file names (thx to Muhammad
    Muquit).
* Other changes
  - Maximum number of services increased from 64 to 256 when poll() is used.

### Version 4.15, 2006.03.11, urgency: LOW
* Release notes
  - There are a lot of new features in this version.  I recommend
    to test it well before upgrading your mission-critical systems.
* Bugfixes
  - Fix for pthreads on Solaris 10.
  - Attempt to autodetect socklen_t type in configure script.
  - Default threading model changed to pthread for better portability.
  - DH parameters are not included in the certificate by default.
* New features sponsored by Software House http://www.swhouse.com/
  - Most SSL-related options (including client, cert, key) are now
    available on service-level, so it is possible to have an SSL
    client and an SSL server in a single stunnel process.
  - Windows CE (version 3.0 and higher) support.
* New features
  - Client mode CONNECT protocol support (RFC 2817 section 5.2).
    http://www.ietf.org/rfc/rfc2817.txt
  - Retrying exec+connect services added.
* File locations are more compliant to Filesystem Hierarchy Standard 2.3
  - configuration and certificates are in $prefix/etc/stunnel/
  - binaries are in $prefix/sbin/
  - default pid file is $prefix/var/run/stunnel.pid
  - manual is $prefix/man/man8/stunnel.8
  - other docs are in $prefix/share/doc/stunnel/
  - libstunnel is in $prefix/lib
  - chroot directory is setup in $prefix/var/lib/stunnel/
    this directory is chmoded 1770 and group nogroup

### Version 4.14, 2005.11.02, urgency: HIGH
* Bugfixes
  - transfer() fixed to avoid random stalls introduced in version 4.12.
  - poll() error handing bug fixed.
  - Checking for dynamic loader libraries added again.
  - Default pidfile changed from $localstatedir/run/stunnel.pid
    to $localstatedir/stunnel/stunnel.pid.
  - Basic SSL library initialization moved to the beginning of execution.
* Release notes
  - This is an important bugfix release.  Upgrade is recommended.

### Version 4.13, 2005.10.21, urgency: MEDIUM
* DLLs for OpenSSL 0.9.7i included because protection faults were reported
  in 0.9.8 and 0.9.8a.
* New features
  - Libwrap code is executed as a separate process (no more delays due
    to a global and potentially long critical section).
* Bugfixes
  - Problem with zombies in UCONTEXT threading fixed.
  - Workaround for non-standard makecontext() uc_stack.ss_sp parameter
    semantics on SGI IRIX.
  - Protection fault in signals handling on IRIX fixed.
  - Problem finding pthread library on AIX fixed.
  - size_t printf() fixed in stack_info() (the previous fix didn't work).
  - socklen_t is used instead of int where required.

### Version 4.12, 2005.09.29, urgency: MEDIUM
* New features
  - Win32 installer added.
  - New Win32 commandline options: -start and -stop.
  - Log level and thread number are reported to syslog.
  - DLLs for OpenSSL 0.9.8.
  - stunnel.spec updated by neeo <neeo@irc.pl>.
* Bugfixes
  - Use of broken poll() is disabled on Mac OS X.
  - Yet another transfer() infinite loop condition fixed.
  - Workaround for a serious M$ bug (KB177346).
  - IPv6 DLLs allocation problem resulting in GPF on W2K fixed.
  - zlib added to shared libraries (OpenSSL may need it).
  - size_t printf() fixed in stack_info().
* Release notes
  - This is a bugfix release.  Upgrade is recommended.

### Version 4.11, 2005.07.09, urgency: MEDIUM
* New features
  - New ./configure option --with-threads to select thread model.
  - ./configure option --with-tcp-wrappers renamed to --disable-libwrap.
    I hope the meaning of the option is much more clear, now.
* Bugfixes
  - Workaround for non-standard makecontext() uc_stack.ss_sp parameter
    semantics on Sparc/Solaris 9 and earlier.
  - scan_waiting_queue() no longer drops contexts.
  - Inetd mode GPFs with UCONTEXT fixed.
  - Cleanup context is no longer used.
  - Releasing memory of the current context is delayed.
  - Win32 headers reordered for Visual Studio 7.
  - Some Solaris compilation warnings fixed.
  - Rejected inetd mode without 'connect' or 'exec'.
* Release notes
  - UCONTEXT threading seems stable, now.  Upgrade is recommended.

### Version 4.10, 2005.04.23, urgency: LOW/EXPERIMENTAL
* DLLs for OpenSSL 0.9.7g.
* Bugfixes
  - Missing locking on Win32 platform was added (thx to Yi Lin
    <yi.lin@convergys.com>)
  - Some problems with closing SSL fixed.
* New features
  - New UCONTEXT user-level non-preemptive threads model is used
    on systems that support SYSV-compatible ucontext.h.
  - Improved stunnel3 script with getopt-compatible syntax.
* Release notes
  - This version should be thoroughly tested before using it in the
    mission-critical environment.

### Version 4.09, 2005.03.26, urgency: MEDIUM
* DLLs for OpenSSL 0.9.7f.
* Bugfixes
  - Compilation problem with undeclared socklen_t fixed.
  - TIMEOUTclose is not used when there is any data in the buffers.
  - Stunnel no longer relies on close_notify with SSL 2.0 connections,
    since SSL 2.0 protocol does not have any alerts defined.
  - Closing SSL socket when there is some data in SSL output buffer
    is detected and reported as an error.
  - Install/chmod race condition when installing default certificate fixed.
  - Stunnel no longer installs signal_handler on ignored signals.

### Version 4.08, 2005.02.27, urgency: LOW
* New features
  - New -quiet option was added to install NT service without a message box.
* Bugfixes
  - Using $(DESTDIR) in tools/Makefile.am.
  - Define NI_NUMERICHOST and NI_NUMERICSERV when needed.
  - Length of configuration file line increased from 256B to 16KB.
  - Stunnel sends close_notify when a close_notify is received from SSL
    peer and all remaining data is sent to SSL peer.
  - Some fixes for bugs detected by the watchdog.
* Release notes
  - There were many changes in the transfer() function (the main loop).
  - This version should be thoroughly tested before using it in the
    mission-critical environment.

### Version 4.07, 2005.01.03, urgency: MEDIUM
* Bugfixes
  - Problem with infinite poll() timeout negative, but not equal to -1 fixed.
  - Problem with a file descriptor ready to be read just after a non-blocking
    connect call fixed.
  - Compile error with EAI_NODATA not defined or equal to EAI_NONAME fixed.
  - IP address and TCP port textual representation length (IPLEN) increased
    to 128 bytes.
  - OpenSSL engine support is only used if engine.h header file exists.
  - Broken NT Service mode on Win32 platform fixed.
  - Support for IPv4-only Win32 machines restored.

### Version 4.06, 2004.12.26, urgency: LOW
* New feature sponsored by SURFnet http://www.surfnet.nl/
  - IPv6 support (to be enabled with ./configure --enable-ipv6).
* New features
  - poll() support - no more FD_SETSIZE limit!
  - Multiple connect=host:port options are allowed in a single service
    section.  Remote hosts are connected using round-robin algorithm.
    This feature is not compatible with delayed resolver.
  - New 'compression' option to enable compression.  To use zlib
    algorithm you have to enable it when building OpenSSL library.
  - New 'engine' option to select a hardware engine.
  - New 'TIMEOUTconnect' option with 10 seconds default added.
  - stunnel3 perl script to emulate version 3.x command line options.
  - French manual updated by Bernard Choppy <choppy AT free POINT fr>.
  - A watchdog to detect transfer() infinite loops added.
  - Configuration file comment character changed from '#' to ';'.
    '#' will still be recognized to keep compatibility.
  - MT-safe getaddrinfo() and getnameinfo() are used where available
    to get better performance on resolver calls.
  - Automake upgraded from 1.4-p4 to 1.7.9.
* Bugfixes
  - log() changed to s_log() to avoid conflicts on some systems.
  - Common CRIT_INET critical section introduced instead of separate
    CRIT_NTOA and CRIT_RESOLVER to avoid potential problems with
    libwrap (TCP Wrappers) library.
  - CreateThread() finally replaced with _beginthread() on Win32.
  - make install creates $(localstatedir)/stunnel.
    $(localstatedir)/stunnel/dev/zero is also created on Solaris.
  - Race condition with client session cache fixed.
  - Other minor bugfixes.
* Release notes
  - Win32 port requires Winsock2 to work.
    Some Win95 systems may need a free update from Microsoft.
    http://www.microsoft.com/windows95/downloads/
  - Default is *not* to use IPv6 '::' for accept and '::1' for
    connect.  For example to accept pop3s on IPv6 you could use:
    'accept = :::995'.  I hope the new syntax is clear enough.

### Version 4.05, 2004.02.14, urgency: MEDIUM
* New feature sponsored by SURFnet http://www.surfnet.nl/
  - Support for CIFS aka SMB protocol SSL negotiation.
* New features
  - CRL support with new CRLpath and CRLfile global options.
  - New 'taskbar' option on Win32 (thx to Ken Mattsen
    <ken.Mattsen@roxio.com>).
  - New -fd command line parameter to read configuration
    from a specified file descriptor instead of a file.
  - accept is reported as error when no '[section]' is
    defined (in stunnel 4.04 it was silently ignored causing
    problems for lusers who did not read the fine manual).
  - Use fcntl() instead of ioctlsocket() to set socket
    nonblocking where it is supported.
  - Basic support for hardware engines with OpenSSL >= 0.9.7.
  - French manual by Bernard Choppy <choppy@imaginet.fr>.
  - Thread stack size reduced to 64KB for maximum scalability.
  - Added optional code to debug thread stack usage.
  - Support for nsr-tandem-nsk (thx to Tom Bates <tom.bates@hp.com>).
* Bugfixes
  - TCP wrappers code moved to CRIT_NTOA critical section
    since it uses static inet_ntoa() result buffer.
  - SSL_ERROR_SYSCALL handling problems fixed.
  - added code to retry nonblocking SSL_shutdown() calls.
  - Use FD_SETSIZE instead of 16 file descriptors in inetd
    mode.
  - fdscanf groks lowercase protocol negotiation commands.
  - Win32 taskbar GDI objects leak fixed.
  - Libwrap detection bug in ./configure script fixed.
  - grp.h header detection fixed for NetBSD and possibly
    other systems.
  - Some other minor updates.

### Version 4.04, 2003.01.12, urgency: MEDIUM
* New feature sponsored by SURFnet http://www.surfnet.nl/
  - Encrypted private key can be used with Win32 GUI.
* New features
  - New 'options' configuration option to setup
    OpenSSL library hacks with SSL_CTX_set_options().
  - 'service' option also changes the name for
    TCP Wrappers access control in inetd mode.
  - Support for BeOS (thx to Mike I. Kozin <mik@sbor.net>)
  - SSL is negotiated before connecting remote host
    or spawning local process whenever possible.
  - REMOTE_HOST variable is always placed in the
    enrivonment of a process spawned with 'exec'.
  - Whole SSL error stack is dumped on errors.
  - 'make cert' rule is back (was missing since 4.00).
  - Manual page updated (special thanks to Brian Hatch).
  - TODO updated.
* Bugfixes
  - Major code cleanup (thx to Steve Grubb <linux_4ever@yahoo.com>).
  - Unsafe functions are removed from SIGCHLD handler.
  - Several bugs in auth_user() fixed.
  - Incorrect port when using 'local' option fixed.
  - OpenSSL tools '-rand' option is no longer directly
    used with a device (like '/dev/urandom').
    Temporary random file is created with 'dd' instead.
* DLLs for OpenSSL 0.9.7.

### Version 4.03, 2002.10.27, urgency: HIGH
* NT Service (broken since 4.01) is operational again.
* Memory leak in FORK environments fixed.
* sigprocmask() mistake corrected.
* struct timeval is reinitialized before select().
* EAGAIN handled in client.c for AIX.
* Manual page updated.

### Version 4.02, 2002.10.21, urgency: HIGH
* Serious bug in ECONNRESET handling fixed.

### Version 4.01, 2002.10.20, urgency: MEDIUM
* New features
  - OpenVMS support.
  - Polish manual and some manual updates.
  - 'service' option added on Win32 platform.
  - Obsolete FAQ has been removed.
  - Log file is created with 0640 mode.
  - exec->connect service sections (need more testing).
* Bugfixes
  - EINTR ingored in main select() loop.
  - Fixed problem with stunnel closing connections on
    TIMEOUTclose before all the data is sent.
  - Fixed EWOULDBLOCK on writesocket problem.
  - Potential DOS in Win32 GUI fixed.
  - Solaris compilation problem fixed.
  - Libtool configuration problems fixed.
  - Signal mask is cleared just before exec in local mode.
  - Accepting sockets and log file descriptors are no longer
    leaked to the child processes.
### Special thanks to Steve Grubb for the source code audit.

### Version 4.00, 2002.08.30, urgency: LOW
* New features sponsored by MAXIMUS http://www.maximus.com/
  - New user interface (config file).
  - Single daemon can listen on multiple ports, now.
  - Native Win32 GUI added.
  - Native NT/2000/XP service added.
  - Delayed DNS lookup added.
* Other new features
  - All the timeouts are now configurable including
    TIMEOUTclose that can be set to 0 for MSIE and other
    buggy clients that do not send close_notify.
  - Stunnel process can be chrooted in a specified directory.
  - Numerical values for setuid() and setgid() are allowed, now.
  - Confusing code for setting certificate defaults introduced in
    version 3.8p3 was removed to simplify stunnel setup.
    There are no built-in defaults for CApath and CAfile options.
  - Private key file for a certificate can be kept in a separate
    file.  Default remains to keep it in the cert file.
  - Manual page updated.
  - New FHS-compatible build system based on automake and libtool.
* Bugfixes
  - `SSL socket closed on SSL_write' problem fixed.
  - Problem with localtime() crashing Solaris 8 fixed.
  - Problem with tcp wrappers library detection fixed.
  - Cygwin (http://www.cygwin.com/) support added.
  - __svr4__ macro defined for Sun C/C++ compiler.
* DLLs for OpenSSL 0.9.6g.

### Version 3.22, 2001.12.20, urgency: HIGH
* Format string bug fixed in protocol.c
  smtp, pop3 and nntp in client mode were affected.
  (stunnel clients could be attacked by malicious servers)
* Certificate chain can be supplied with -p option or in stunnel.pem.
* Problem with -r and -l options used together fixed.
* memmove() instead of memcpy() is used to move data in buffers.
* More detailed information about negotiated ciphers is printed.
* New ./configure options: '--enable-no-rsa' and '--enable-dh'.

### Version 3.21c, 2001.11.11, urgency: LOW
* autoconf scripts upgraded to version 2.52.
* Problem with pthread_sigmask on Darwin fixed (I hope).
* Some documentation typos corrected.
* Attempt to ignore EINTR in transfer().
* Shared library version reported on startup.
* DLLs for OpenSSL 0.9.6b.

### Version 3.21b, 2001.11.03, urgency: MEDIUM
* File descriptor leak on failed connect() fixed.

### Version 3.21a, 2001.10.31, urgency: MEDIUM
* Small bug in Makefile fixed.

### Version 3.21, 2001.10.31, urgency: MEDIUM
* Problem with errno and posix threads fixed.
* It is assumed that system has getopt() if it has getopt.h header file.
* SSL_CLIENT_DN and SSL_CLIENT_I_DN environment variables set in local mode
  (-l) process.  This feature doesn't work if
  client mode (-c) or protocol negotiation (-n) is used.
* Winsock error descriptions hardcoded (English version only).
* SetConsoleCtrlHandler() used to handle CTRL+C, logoff and shutdown on Win32.
* Stunnel always requests peer certificate with -v 0.
* sysconf()/getrlimit() used to calculate number of clients allowed.
* SSL mode changed for OpenSSL >= 0.9.6.
* close-on-exec option used to avoid socket inheriting.
* Buffer size increased from 8KB to 16KB.
* fdscanf()/fdprintf() changes:
   - non-blocking socket support,
   - timeout after 1 minute of inactivity.
* auth_user() redesigned to force 1 minute timeout.
* Some source arrangement towards 4.x architecture.
* No need for 'goto' any more.
* New Makefile 'test' rule.  It performs basic test of
  standalone/inetd, remote/local and server/client mode.
* pop3 server mode support added.

### Version 3.20, 2001.08.15, urgency: LOW
* setsockopt() optlen set according to the optval for Solaris.
* Minor NetBSD compatibility fixes by Martti Kuparinen.
* Minor MSVC 6.0 compatibility fixes by Patrick Mayweg.
* SSL close_notify timeout reduced to 10 seconds of inactivity.
* Socket close instead of reset on close_notify timeout.
* Some source arrangement and minor bugfixes.

### Version 3.19, 2001.08.10, urgency: MEDIUM
* Critical section added around non MT-safe TCP Wrappers code.
* Problem with 'select: Interrupted system call' error fixed.
* errno replaced with get_last_socket_error() for Win32.
* Some FreeBSD/NetBSD patches to ./configure from Martti Kuparinen.
* Local mode process pid logged.
* Default FQDN (localhost) removed from stunnel.cnf
* ./configure changed to recognize POSIX threads library on OSF.
* New -O option to set socket options.

### Version 3.18, 2001.07.31, urgency: MEDIUM
* MAX_CLIENTS is calculated based on FD_SETSIZE, now.
* Problems with closing SSL in transfer() fixed.
* -I option to bind a static local IP address added.
* Debug output of info_callback redesigned.

### Version 3.17, 2001.07.29, urgency: MEDIUM
* Problem with GPF on exit with active threads fixed.
* Timeout for transfer() function added:
   - 1 hour if socket is open for read
   - 1 minute if socket is closed for read

### Version 3.16, 2001.07.22, urgency: MEDIUM
* Some transfer() bugfixes/improvements.
* STDIN/STDOUT are no longer assumed to be non-socket descriptors.
* Problem with --with-tcp-wrappers patch fixed.
* pop3 and nntp support bug fixed by Martin Germann.
* -o option to append log messages to a file added.
* Changed error message for SSL error 0.

### Version 3.15, 2001.07.15, urgency: MEDIUM
* Serious bug resulting in random transfer() hangs fixed.
* Separate file descriptors are used for inetd mode.
* -f (foreground) logs are now stamped with time.
* New ./configure option: --with-tcp-wrappers by Brian Hatch.
* pop3 protocol client support (-n pop3) by Martin Germann.
* nntp protocol client support (-n nntp) by Martin Germann.
* RFC 2487 (smtp STARTTLS) client mode support.
* Transparency support for Tru64 added.
* Some #includes for AIX added.

### Version 3.14, 2001.02.21, urgency: LOW
* Pidfile creation algorithm has been changed.

### Version 3.13, 2001.01.25, urgency: MEDIUM
* pthread_sigmask() argument in sthreads.c corrected.
* OOB data is now handled correctly.

### Version 3.12, 2001.01.24, urgency: LOW
* Attempted to fix problem with zombies in local mode.
* Patch for 64-bit machines by Nalin Dahyabhai <nalin@redhat.com> applied.
* Tiny bugfix for OSF cc by Dobrica Pavlinusic <dpavlin@rot13.org> added.
* PORTS file updated.

### Version 3.11, 2000.12.21, urgency: MEDIUM
* New problem with zombies fixed.
* Attempt to be integer-size independent.
* SIGHUP handler added.

### Version 3.10, 2000.12.19, urgency: MEDIUM
* Internal thread synchronization code added.
* libdl added to stunnel dependencies if it exists.
* Manpage converted to sdf format.
* stunnel deletes pid file before attempting to create it.
* Documentation updates.
* -D option now takes [facility].level as argument.  0-7 still supported.
* Problems with occasional zombies in FORK mode fixed.
* 'stunnel.exe' rule added to Makefile.
  You can cross-compile stunnel.exe on Unix, now.
  I'd like to be able to compile OpenSSL this way, too...

### Version 3.9, 2000.12.13, urgency: HIGH
* Updated temporary key generation:
   - stunnel is now honoring requested key-lengths correctly,
   - temporary key is changed every hour.
* transfer() no longer hangs on some platforms.
  Special thanks to Peter Wagemans for the patch.
* Potential security problem with syslog() call fixed.

### Version 3.8p4, 2000.06.25  bri@stunnel.org:
* fixes for Windows platform

### Version 3.8p3, 2000.06.24  bri@stunnel.org:
* Compile time definitions for the following:
    --with-cert-dir
    --with-cert-file
    --with-pem-dir
    --enable-ssllib-cs
* use daemon() function instead of daemonize, if available
* fixed FreeBSD threads checking (patch from robertw@wojo.com)
* added -S flag, allowing you to choose which default verify
  sources to use
* relocated service name output logging until after log_open.
  (no longer outputs log info to inetd socket, causing bad SSL)
* -V flag now outputs the default values used by stunnel
* Removed DH param generation in Makefile.in
* Moved stunnel.pem to sample.pem to keep people from blindly using it
* Removed confusing stunnel.pem check from Makefile.

* UPGRADE NOTE: this version seriously changes several previous stunnel
  default behaviours.  There are no longer any default cert file/dirs
  compiled into stunnel, you must use the --with-cert-dir and
  --with-cert-file configure arguments to set these manually, if desired.
  Stunnel does not use the underlying ssl library defaults by default
  unless configured with --enable-ssllib-cs.  Note that these can always
  be enabled at run time with the -A,-a, and -S flags.
  Additionally, unless --with-pem-dir is specified at compile time,
  stunnel will default to looking for stunnel.pem in the current directory.

### Version 3.8p2, 2000.06.13  bri@stunnel.org:
* Fixes for Win32 platform
* Minor output formatting changes
* Fixed version number in files

### Version 3.8p1, 2000.06.11  bri@stunnel.org:
* Added rigorous PRNG seeding
* PID changes (and related security-fix)
* Man page fixes
* Client SSL Session-IDs now used
* -N flag to specify tcpwrapper service name

### Version 3.8, 2000.02.24:
* Checking for threads in c_r library for FreeBSD.
* Some compatibility fixes for Ultrix.
* configure.in has been cleaned up.
  Separate directories for SSL certs and SSL libraries/headers
  are no longer supported.  SSL ports maintainers should create
  softlinks in the main openssl directory if necessary.
* Added --with-ssl option to specify SSL directory.
* Added setgid (-g) option.
  (Special thanks to Brian Hatch for his feedback and support)
* Added pty.c based on a Public Domain code by Tatu Ylonen
* Distribution files are now signed with GnuPG

### Version 3.7, 2000.02.10:
* /usr/pkg added to list of possible SSL directories for pkgsrc installs
  of OpenSSL under NetBSD.
* Added the -s option, which setuid()s to the specified user when running
  in daemon mode. Useful for cyrus imapd.
  (both based on patch by George Coulouris)
* PTY code ported to Solaris.  The port needs some more testing.
* Added handler for SIGINT.
* Added --with-random option to ./configure script.
* Fixed some problems with autoconfiguration on Solaris and others.
  It doesn't use config.h any more.
* /var/run changed to @localstatedir@/stunnel for better portability.
  The directory is chmoded a=rwx,+t.
* FAQ has been updated.

### 3.6 2000.02.03
* Automatic RFC 2487 detection based on patch by Pascual Perez and Borja Perez.
* Non-blocking sockets not used by default.
* DH support is disabled by default.
* (both can be enabled in ssl.c)

### 3.5 2000.02.02
* Support for openssl 0.9.4 added.
* /usr/ssl added to configure by Christian Zuckschwerdt.
* Added tunneling for PPP through the addition of PTY handling.
* Added some documentation.

### 3.4a 1999.07.13 (bugfix release)
* Problem with cipher negotiation fixed.
* setenv changed to putenv.

### 3.4 1999.07.12
* Local transparent proxy added with LD_PRELOADed shared library.
* DH code rewritten.
* Added -C option to set cipher list.
* stderr fflushed after fprintf().
* Minor portability bugfixes.
* Manual updated (but still not perfect).

### 3.3 1999.06.18
* Support for openssl 0.9.3 added.
* Generic support for protocol negotiation added (protocol.c).
* SMTP protocol negotiation support for Netscape client added.
* Transparent proxy mode (currently works on Linux only).
* SO_REUSEADDR enabled on listening socket in daemon mode.
* ./configure now accepts --prefix parameter.
* -Wall is only used with gcc compiler.
* Makefile.in and configure.in updated.
* SSL-related functions moved to a separate file.
* vsprintf changed to vsnprintf in log.c on systems have it.
* Pidfile in /var/run added for daemon mode.
* RSAref support fix (not tested).
* Some compatibility fixes for Solaris and NetBSD added.

### 3.2 1999.04.28
* RSAref support (not tested).
* Added full duplex with non-blocking sockets.
* RST sent instead of FIN on peer error (on error peer
  socket is reset - not just closed).
* RSA temporary key length changed back to 512 bits to fix
  a problem with Netscape.
* Added NO_RSA for US citizens having problems with patents.

### 3.1 1999.04.22
* Changed -l syntax (first argument specified is now argv[0]).
* Fixed problem with options passed to locally executed daemon.
* Fixed problem with ':' passed to libwrap in a service name:
  - ':' has been changed to '.';
  - user can specify his own service name as an argument.
* RSA temporary key length changed from 512 to 1024 bits.
* Added safecopy to avoid buffer overflows in stunnel.c.
* Fixed problems with GPF after unsuccessful resolver call
  and incorrect parameters passed to getopt() in Win32.
* FAQ updated.

### 3.0 1999.04.19
* Some bugfixes.
* FAQ added.

### 3.0b7 1999.04.14
* Win32 native port fixed (looks quite stable).
* New transfer() function algorithm.
* New 'make cert' to be compatible with openssl-0.9.2b.
* Removed support for memory leaks debugging.

### 3.0b6 1999.04.01
* Fixed problems with session cache (by Adam).
* Added client mode session cache.
* Source structure, autoconf script and Makefile changed.
* Added -D option to set debug level.
* Added support for memory leaks debugging
  (SSL library needs to be compiled with -DMFUNC).

### 3.0b5 1999.03.25
* Lots of changes to make threads work.
* Peer (client and server) authentication works!
* Added -V option to display version.

### 3.0b4 1999.03.22
* Early POSIX threads implementation.
* Work on porting to native Win32 application started.

### 3.0b3 1999.03.05
* Improved behavior on heavy load.

### 3.0b2 1999.03.04
* Fixed -v parsing bug.

### 3.0b1 1999.01.18
* New user interface.
* Client mode added.
* Peer certificate verification added (=strong authentication).
* Win32 port added.
* Other minor problems fixed.

### 2.1 1998.06.01
* Few bugs fixed.

### 2.0 1998.05.25
* Remote mode added!
* Standalone mode added!
* tcpd functionality added by libwrap utilization.
* DH callbacks removed by kravietZ.
* bind loopback on Intel and other bugs fixed by kravietZ.
* New manual page by kravietZ & myself.

### 1.6 1998.02.24
* Linux bind fix.
* New TODO ideas!

### 1.5 1998.02.24
* make_sockets() implemented with Internet sockets instead
  of Unix sockets for better compatibility.
  (i.e. to avoid random data returned by getpeername(2))
  This feature can be disabled in stunnel.c.

### 1.4 1998.02.16
* Ported to HP-UX, Solaris and probably other UNIXes.
* Autoconfiguration added.

### 1.3 1998.02.14
* Man page by Pawel Krawczyk <kravietz@ceti.com.pl> added!
* Copyrights added.
* Minor errors corrected.

### 1.2 1998.02.14
* Separate certificate for each service added.
* Connection logging support.

### 1.1 1998.02.14
* Callback functions added by Pawel Krawczyk <kravietz@ceti.com.pl>.

### 1.0 1998.02.11
* First version with SSL support
  - special thx to Adam Hernik <adas@infocentrum.com>.

### 0.1 1998.02.10
* Testing skeleton.
