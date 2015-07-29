# Process this file with autoconf to produce a configure script.

AC_INIT([stunnel],[4.09])
AC_MSG_NOTICE([**************************************** initialization])
AC_CONFIG_AUX_DIR(auto)
AM_INIT_AUTOMAKE(stunnel, 4.09)
AC_CONFIG_SRCDIR(src/stunnel.c)

AC_CANONICAL_HOST
AC_SUBST(host)
AC_DEFINE_UNQUOTED(HOST, "$host")

AC_PROG_CC
if test "$GCC" = "yes"; then
CFLAGS="$CFLAGS -Wall -Wshadow -Wcast-align -Wpointer-arith"
fi
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for typedefs, structures, and compiler characteristics
# AC_C_CONST
# AC_TYPE_SIGNAL
# AC_TYPE_SIZE_T
# AC_TYPE_PID_T
# AC_HEADER_TIME

AC_MSG_NOTICE([**************************************** libtool])
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_MSG_NOTICE([**************************************** integer sizes])
AC_CHECK_SIZEOF(unsigned char)
AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)

AC_MSG_NOTICE([**************************************** PTY device files])
AC_CHECK_FILE("/dev/ptmx", AC_DEFINE(HAVE_DEV_PTMX))
AC_CHECK_FILE("/dev/ptc", AC_DEFINE(HAVE_DEV_PTS_AND_PTC))

AC_MSG_NOTICE([**************************************** SSL and entropy])
checkssldir() { :
    if test -f "$1/include/openssl/ssl.h"; then
        AC_DEFINE(HAVE_OPENSSL)
        ssldir="$1"
        return 0
    fi
    if test -f "$1/include/ssl.h"; then
        ssldir="$1"
        return 0
    fi
    return 1
}

# Check for SSL directory
AC_MSG_CHECKING([for SSL directory])
AC_ARG_WITH(ssl,
    [  --with-ssl=DIR          location of installed SSL libraries/include files],
    [
        # Check the specified localtion only
        checkssldir "$withval"
    ],
    [
        # Search default localtions of SSL library
        for maindir in /usr/local /usr/lib /usr/pkg /usr /var/ssl /opt; do
            for dir in $maindir $maindir/openssl $maindir/ssl; do
                checkssldir $dir && break 2
            done
        done
    ]
)
if test -z "$ssldir"; then
    AC_MSG_RESULT([Not found])
    echo
    echo "Couldn't find your SSL library installation dir"
    echo "Use --with-ssl option to fix this problem"
    echo
    exit 1
fi
AC_MSG_RESULT([$ssldir])
AC_SUBST(ssldir)
AC_DEFINE_UNQUOTED(ssldir, "$ssldir")

AC_CHECK_HEADER([$ssldir/include/openssl/engine.h],
    [AC_DEFINE([HAVE_OSSL_ENGINE_H])],
    [AC_MSG_WARN([Openssl engine header not found])])

AC_ARG_WITH(egd-socket,
    [  --with-egd-socket=FILE  Entropy Gathering Daemon socket pathname],
    [EGD_SOCKET="$withval"]
)
if test -n "$EGD_SOCKET" ; then
	AC_DEFINE_UNQUOTED(EGD_SOCKET, "$EGD_SOCKET")
fi

# Check for user-specified random device
AC_ARG_WITH(random,
    [  --with-random=FILE      read randomness from FILE (default=/dev/urandom)],
    [RANDOM_FILE="$withval"],
    [
        # Check for random device
        AC_CHECK_FILE("/dev/urandom",
            [
                RANDOM_FILE="/dev/urandom";
            ]
        )
    ]
)
if test -n "$RANDOM_FILE" ; then
	AC_SUBST(RANDOM_FILE)
	AC_DEFINE_UNQUOTED(RANDOM_FILE, "$RANDOM_FILE")
fi

AC_MSG_NOTICE([**************************************** libraries])
# Checks for standard libraries
AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(dld, shl_load)
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(util, openpty)

# OSF hack instead of simple AC_CHECK_LIB here
AC_MSG_CHECKING([for pthread_create in -lpthread])
    saved_LIBS="$LIBS"
    LIBS="-lpthread $saved_LIBS"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread.h>]], [[pthread_create((void *)0, (void *)0, (void *)0, (void *)0)]])],[AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_LIBPTHREAD)],[AC_MSG_RESULT([no]); LIBS="$saved_LIBS"])

# BSD hack
AC_CHECK_LIB(c_r, pthread_create,
    [LIBS="$LIBS -pthread"; AC_DEFINE(HAVE_LIBPTHREAD)]
)

# Check for libwrap library
AC_MSG_CHECKING([whether to use the libwrap (TCP wrappers) library])
AC_ARG_WITH(tcp-wrappers,
[  --with-tcp-wrappers     Use the libwrap (TCP wrappers) library],
  [
    if test "$withval" = "yes"; then
      AC_MSG_RESULT([yes])
      AC_MSG_CHECKING([for hosts_access in -lwrap])
      saved_LIBS="$LIBS"
      LIBS="-lwrap $LIBS"
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[int hosts_access(); int allow_severity, deny_severity;]], [[hosts_access()]])],[AC_MSG_RESULT([yes]); wrap_LIB="-lwrap"; AC_DEFINE(HAVE_LIBWRAP)],[AC_MSG_RESULT([not found]); exit 1])
      LIBS="$saved_LIBS"
    else
      AC_MSG_RESULT([no])
    fi
  ],
  [
    AC_MSG_RESULT([(default)])
    AC_MSG_CHECKING([for hosts_access in -lwrap])
    saved_LIBS="$LIBS"
    LIBS="-lwrap $saved_LIBS"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[int hosts_access(); int allow_severity, deny_severity;]], [[hosts_access()]])],[AC_MSG_RESULT([yes]); wrap_LIB="-lwrap"; AC_DEFINE(HAVE_LIBWRAP)],[AC_MSG_RESULT([no])])
    LIBS="$saved_LIBS"
  ]
)

# Add BeOS libraries
if test "$host_os" = "beos"; then
LIBS="$LIBS -lbe -lroot -lbind"
fi

# Add SSL includes and libraries
CFLAGS="$CFLAGS -I$ssldir/include"
LIBS="$LIBS -L$ssldir/lib -lssl -lcrypto"

# Check for obsolete RSAref library
AC_MSG_CHECKING([for obsolete RSAref library])
saved_LIBS="$LIBS"
LIBS="$saved_LIBS -lRSAglue -L$prefix/lib -lrsaref"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[AC_MSG_RESULT([yes]); ],[AC_MSG_RESULT([no]); LIBS="$saved_LIBS"])

AC_MSG_NOTICE([**************************************** header files])
# AC_HEADER_DIRENT
# AC_HEADER_STDC
# AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(grp.h unistd.h sys/select.h poll.h sys/poll.h tcpd.h pthread.h sys/ioctl.h util.h pty.h stropts.h sys/filio.h sys/resource.h)

AC_MSG_NOTICE([**************************************** library functions])
AC_CHECK_FUNCS(snprintf vsnprintf openpty _getpty daemon waitpid wait4 sysconf getrlimit pthread_sigmask setgroups localtime_r chroot endhostent setsid getaddrinfo getnameinfo poll)

AC_MSG_NOTICE([**************************************** optional features])
# Use RSA?
AC_MSG_CHECKING([whether to disable RSA support])
AC_ARG_ENABLE(rsa,
[  --disable-rsa           Disable RSA support],
    [AC_MSG_RESULT([yes]); AC_DEFINE(NO_RSA)],
    [AC_MSG_RESULT([no])]
)

# Use DH?
AC_MSG_CHECKING([whether to enable DH support])
AC_ARG_ENABLE(dh,
[  --enable-dh             Enable DH support],
    [AC_MSG_RESULT([yes]); USE_DH=1; AC_DEFINE(USE_DH)],
    [AC_MSG_RESULT([no]); USE_DH=0]
)
AC_SUBST(USE_DH)

# Use IPv6?
AC_MSG_CHECKING([whether to enable IPv6 support])
AC_ARG_ENABLE(ipv6,
[  --enable-ipv6           Enable IPv6 support],
    [AC_MSG_RESULT([yes]); USE_IPv6=1; AC_DEFINE(USE_IPv6)],
    [AC_MSG_RESULT([no]); USE_IPv6=0]
)
AC_SUBST(USE_IPv6)

AC_MSG_NOTICE([**************************************** write the results])
LIBS="$LIBS $wrap_LIB"
CPPFLAGS="$CPPFLAGS -DLIBDIR=\\\"$libdir\\\" -DCONFDIR=\\\"$sysconfdir/stunnel\\\" -DPIDFILE=\\\"$localstatedir/run/stunnel.pid\\\""
AC_CONFIG_FILES([Makefile src/Makefile src/stunnel3 doc/Makefile tools/Makefile tools/stunnel.conf-sample tools/stunnel.init])
AC_OUTPUT

AC_MSG_NOTICE([**************************************** success])
# End of configure.ac
