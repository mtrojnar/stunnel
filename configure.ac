# Process this file with autoconf to produce a configure script.

AC_INIT([stunnel], [4.13])
AC_MSG_NOTICE([**************************************** initialization])
AC_CONFIG_AUX_DIR(auto)
AM_INIT_AUTOMAKE(stunnel, 4.13)
AC_CONFIG_SRCDIR(src/stunnel.c)

AC_CANONICAL_HOST
AC_SUBST(host)
AC_DEFINE_UNQUOTED(HOST, "$host")

AC_PROG_CC
if test "$GCC" = "yes"
then CFLAGS="$CFLAGS -Wall -Wshadow -Wcast-align -Wpointer-arith"
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

AC_MSG_NOTICE([**************************************** libraries])
# Checks for standard libraries
#AC_CHECK_LIB(dl, dlopen)
#AC_CHECK_LIB(dld, shl_load)
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(util, openpty)
AC_CHECK_LIB(z, inflateEnd)

# Add BeOS libraries
if test "$host_os" = "beos"
then LIBS="$LIBS -lbe -lroot -lbind"
fi

AC_MSG_NOTICE([**************************************** header files])
# AC_HEADER_DIRENT
# AC_HEADER_STDC
# AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(ucontext.h pthread.h)
AC_CHECK_HEADERS(sys/select.h poll.h sys/poll.h tcpd.h)
AC_CHECK_HEADERS(sys/ioctl.h sys/filio.h stropts.h)
AC_CHECK_HEADERS(grp.h unistd.h util.h libutil.h sys/resource.h pty.h)

AC_MSG_NOTICE([**************************************** library functions])
# safe string operations
AC_CHECK_FUNCS(snprintf vsnprintf)
# pseudoterminal
AC_CHECK_FUNCS(openpty _getpty)
# Unix
AC_CHECK_FUNCS(daemon waitpid wait4 setsid setgroups chroot)
# limits
AC_CHECK_FUNCS(sysconf getrlimit)
# threads/reentrant functions
AC_CHECK_FUNCS(pthread_sigmask localtime_r)
# threads
AC_CHECK_FUNCS(getcontext __makecontext_v2)
# sockets
AC_CHECK_FUNCS(poll endhostent getaddrinfo getnameinfo)
# poll() is not recommended on Mac OS X <=10.3 and broken on Mac OS X >=10.4
AC_MSG_CHECKING([for broken poll() implementation])
case "$host_os" in
darwin*)
    AC_MSG_RESULT([yes (poll() disabled)])
    AC_DEFINE(BROKEN_POLL)
    ;;
*)
    AC_MSG_RESULT([no])
    ;;
esac

AC_MSG_NOTICE([**************************************** SSL])
checkssldir() { :
    if test -f "$1/include/openssl/ssl.h"
    then AC_DEFINE(HAVE_OPENSSL)
        ssldir="$1"
        return 0
    fi
    if test -f "$1/include/ssl.h"
    then ssldir="$1"
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
if test -z "$ssldir"
then AC_MSG_RESULT([Not found])
    echo
    echo "Couldn't find your SSL library installation dir"
    echo "Use --with-ssl option to fix this problem"
    echo
    exit 1
fi
AC_MSG_RESULT([$ssldir])
AC_SUBST(ssldir)
AC_DEFINE_UNQUOTED(ssldir, "$ssldir")

# Add SSL includes and libraries
CFLAGS="$CFLAGS -I$ssldir/include"
LIBS="$LIBS -L$ssldir/lib -lssl -lcrypto"

# Check for obsolete RSAref library
AC_MSG_CHECKING([for obsolete RSAref library])
saved_LIBS="$LIBS"
LIBS="$saved_LIBS -lRSAglue -L$prefix/lib -lrsaref"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[]], [[]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no]); LIBS="$saved_LIBS"]
)

AC_CHECK_HEADER([$ssldir/include/openssl/engine.h],
    [AC_DEFINE([HAVE_OSSL_ENGINE_H])],
    [AC_MSG_WARN([Openssl engine header not found])])

AC_MSG_NOTICE([**************************************** entropy])

AC_ARG_WITH(egd-socket,
    [  --with-egd-socket=FILE  Entropy Gathering Daemon socket pathname],
    [EGD_SOCKET="$withval"]
)
if test -n "$EGD_SOCKET"
then AC_DEFINE_UNQUOTED(EGD_SOCKET, "$EGD_SOCKET")
fi

# Check for user-specified random device
AC_ARG_WITH(random,
[  --with-random=FILE      read randomness from FILE (default=/dev/urandom)],
    [RANDOM_FILE="$withval"],
    [
        # Check for random device
        AC_CHECK_FILE("/dev/urandom", RANDOM_FILE="/dev/urandom")
    ]
)
if test -n "$RANDOM_FILE"
then AC_SUBST(RANDOM_FILE)
    AC_DEFINE_UNQUOTED(RANDOM_FILE, "$RANDOM_FILE")
fi

AC_MSG_NOTICE([**************************************** thread model])

checkpthreadlib() { :
    # BSD hack -> use alternative libc implementation
    AC_CHECK_LIB(c_r, pthread_create,
        [
            LIBS="$LIBS -pthread"
            HAVE_LIBPTHREAD="yes"
            AC_DEFINE(HAVE_LIBPTHREAD)
        ]
    )

    # OSF hack instead of simple AC_CHECK_LIB here
    AC_MSG_CHECKING([for pthread_create in -lpthread])
    saved_LIBS="$LIBS"
    LIBS="$saved_LIBS -lpthread"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [[#include <pthread.h>]],
            [[pthread_create((void *)0, (void *)0, (void *)0, (void *)0)]]
        )],
        [
            AC_MSG_RESULT([yes])
            HAVE_LIBPTHREAD="yes"
            AC_DEFINE(HAVE_LIBPTHREAD)
        ], [
            AC_MSG_RESULT([no])
            LIBS="$saved_LIBS"
        ]
    )
}

AC_ARG_WITH(threads,
[  --with-threads=model    select threading model (ucontext/pthread/fork)],
[
    case "$withval" in
        ucontext)
            AC_MSG_NOTICE([UCONTEXT mode selected])
            AC_DEFINE(USE_UCONTEXT)
            ;;
        pthread)
            checkpthreadlib
            AC_MSG_NOTICE([PTHREAD mode selected])
            AC_DEFINE(USE_PTHREAD)
            ;;
        fork)
            AC_MSG_NOTICE([FORK mode selected])
            AC_DEFINE(USE_FORK)
            ;;
        *)
            echo
            echo "Unknown thread model \"$withval\""
            echo
            exit 1
            ;;
    esac
], [
    if test "$ac_cv_func_getcontext" = "yes" -a "$ac_cv_header_ucontext_h" = "yes"
    then AC_MSG_NOTICE([UCONTEXT thread model detected])
        AC_DEFINE(USE_UCONTEXT)
    else
        checkpthreadlib
        if test "$HAVE_LIBPTHREAD" = "yes" -a "$ac_cv_header_pthread_h" = "yes"
        then AC_MSG_NOTICE([PTHREAD thread model detected])
            AC_DEFINE(USE_PTHREAD)
        else AC_MSG_NOTICE([FORK thread model detected])
            AC_DEFINE(USE_FORK)
        fi
    fi
])


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
    [AC_MSG_RESULT([yes]); AC_DEFINE(USE_DH)],
    [AC_MSG_RESULT([no])]
)
AC_SUBST(USE_DH)

# Use IPv6?
AC_MSG_CHECKING([whether to enable IPv6 support])
AC_ARG_ENABLE(ipv6,
[  --enable-ipv6           Enable IPv6 support],
    [AC_MSG_RESULT([yes]); AC_DEFINE(USE_IPv6)],
    [AC_MSG_RESULT([no])]
)
AC_SUBST(USE_IPv6)

# Disable use of libwrap (TCP wrappers)
# it should be the last check!
AC_MSG_CHECKING([whether to disable TCP wrappers library support])
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       Disable TCP wrappers library support],
    [AC_MSG_RESULT([yes])],
    [
        AC_MSG_RESULT([no (autodetecting)])
        AC_MSG_CHECKING([for hosts_access in -lwrap])
        saved_LIBS="$LIBS"
        LIBS="$saved_LIBS -lwrap"
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [[int hosts_access(); int allow_severity, deny_severity;]],
                [[hosts_access()]]
            )],
            [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_LIBWRAP)],
            [AC_MSG_RESULT([no]), LIBS="$saved_LIBS"]
        )
    ]
)

AC_MSG_NOTICE([**************************************** write the results])
CPPFLAGS="$CPPFLAGS -DLIBDIR=\\\"$libdir\\\" -DCONFDIR=\\\"$sysconfdir/stunnel\\\" -DPIDFILE=\\\"$localstatedir/run/stunnel.pid\\\""
AC_CONFIG_FILES([Makefile src/Makefile src/stunnel3 doc/Makefile tools/Makefile tools/stunnel.conf-sample tools/stunnel.init])
AC_OUTPUT

AC_MSG_NOTICE([**************************************** success])
# End of configure.ac
