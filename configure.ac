# Process this file with autoconf to produce a configure script.

AC_INIT([stunnel],[4.29])
AC_MSG_NOTICE([**************************************** initialization])
AC_CONFIG_AUX_DIR(auto)
AM_INIT_AUTOMAKE(stunnel, 4.29)
AC_CONFIG_SRCDIR(src/stunnel.c)

AC_CANONICAL_HOST
AC_SUBST(host)
AC_DEFINE_UNQUOTED(HOST, "$host")
define([esc], [`echo ]$1[ | tr abcdefghijklmnopqrstuvwxyz.- ABCDEFGHIJKLMNOPQRSTUVWXYZ__ | tr -dc ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_`])
AC_DEFINE_UNQUOTED(esc(CPU_$host_cpu))
AC_DEFINE_UNQUOTED(esc(VENDOR_$host_vendor))
AC_DEFINE_UNQUOTED(esc(OS_$host_os))

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

AC_MSG_NOTICE([**************************************** types])
AC_CHECK_SIZEOF(unsigned char)
AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)

AC_MSG_CHECKING([for socklen_t])
AC_EGREP_HEADER(socklen_t, sys/socket.h,
    AC_MSG_RESULT([yes]),
    AC_MSG_RESULT([no (defined as int)])
    AC_DEFINE(socklen_t, int))

AC_MSG_NOTICE([**************************************** PTY device files])
AC_CHECK_FILE("/dev/ptmx", AC_DEFINE(HAVE_DEV_PTMX))
AC_CHECK_FILE("/dev/ptc", AC_DEFINE(HAVE_DEV_PTS_AND_PTC))

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

AC_MSG_NOTICE([**************************************** default group])
AC_MSG_CHECKING([for default group])
DEFAULT_GROUP=nobody
grep '^nogroup:' /etc/group >/dev/null && DEFAULT_GROUP=nogroup
AC_MSG_RESULT([$DEFAULT_GROUP])
AC_SUBST(DEFAULT_GROUP)

AC_MSG_NOTICE([**************************************** header files])
# AC_HEADER_DIRENT
# AC_HEADER_STDC
# AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(ucontext.h pthread.h)
AC_CHECK_HEADERS(sys/select.h poll.h sys/poll.h tcpd.h)
AC_CHECK_HEADERS(sys/ioctl.h sys/filio.h stropts.h)
AC_CHECK_HEADERS(grp.h unistd.h util.h libutil.h sys/resource.h pty.h)
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_MEMBERS([struct msghdr.msg_control],
  [AC_DEFINE([HAVE_MSGHDR_MSG_CONTROL])], [],
  [@%:@include <sys/socket.h>])

AC_MSG_NOTICE([**************************************** libraries])
# Checks for standard libraries
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(yp_get_default_domain, nsl)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(util, openpty)
# Checks for dynamic loader and zlib needed by OpenSSL
AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(dld, shl_load)
AC_CHECK_LIB(z, inflateEnd)

# Add BeOS libraries
if test "$host_os" = "beos"
then LIBS="$LIBS -lbe -lroot -lbind"
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
    checkpthreadlib
    if test "$HAVE_LIBPTHREAD" = "yes" -a "$ac_cv_header_pthread_h" = "yes"
    then AC_MSG_NOTICE([PTHREAD thread model detected])
        AC_DEFINE(USE_PTHREAD)
    else if test "$ac_cv_func_getcontext" = "yes" -a "$ac_cv_header_ucontext_h" = "yes"
        then AC_MSG_NOTICE([UCONTEXT thread model detected])
            AC_DEFINE(USE_UCONTEXT)
        else AC_MSG_NOTICE([FORK thread model detected])
            AC_DEFINE(USE_FORK)
        fi
    fi
])

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
AC_CHECK_FUNCS(poll endhostent getnameinfo)
# Tru64 UNIX has getaddrinfo() but has it renamed in libc as
# something else so we must include <netdb.h> to get the
# redefinition.
AC_MSG_CHECKING([for getaddrinfo])
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>]],
        [[getaddrinfo(NULL, NULL, NULL, NULL);]],)],
    [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_GETADDRINFO)],
    [AC_MSG_RESULT([no])])
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
        for maindir in /usr/local /usr/lib /usr/pkg /opt /usr; do
            for dir in $maindir/ssl/fips $maindir/ssl/fips-1.0 \
                    $maindir/ssl $maindir/openssl $maindir; do
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
LIBS="$saved_LIBS -lRSAglue -L$libdir -lrsaref"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM([[]], [[]])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no]); LIBS="$saved_LIBS"]
)

AC_CHECK_HEADER([$ssldir/include/openssl/engine.h],
    [AC_DEFINE([HAVE_OSSL_ENGINE_H])],
    [AC_MSG_WARN([Openssl engine header not found])])

AC_MSG_NOTICE([**************************************** optional features])
# Use RSA?
AC_MSG_CHECKING([whether to disable RSA support])
AC_ARG_ENABLE(rsa,
[  --disable-rsa           Disable RSA support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([no])
                ;;
            no) AC_MSG_RESULT([yes])
                AC_DEFINE(NO_RSA)
                ;;
            *) AC_MSG_ERROR([bad value ${enableval}])
                ;;
        esac
    ],
    [AC_MSG_RESULT([no])]
)

# Use DH?
AC_MSG_CHECKING([whether to enable DH support])
AC_ARG_ENABLE(dh,
[  --enable-dh             Enable DH support],
    [
        case "$enableval" in
            yes)
                AC_MSG_RESULT([yes])
                USE_DH=1
                AC_DEFINE(USE_DH)
                ;;
            no) AC_MSG_RESULT([no])
                ;;
            *) AC_MSG_ERROR([bad value ${enableval}])
                ;;
        esac
    ],
    [AC_MSG_RESULT([no])]
)
AC_SUBST(USE_DH)

# Use IPv6?
AC_MSG_CHECKING([whether to enable IPv6 support])
AC_ARG_ENABLE(ipv6,
[  --enable-ipv6           Enable IPv6 support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                AC_DEFINE(USE_IPv6)
                ;;
            no) AC_MSG_RESULT([no])
                ;;
            *) AC_MSG_ERROR([bad value ${enableval}])
                ;;
        esac
    ],
    [AC_MSG_RESULT([yes]); AC_DEFINE(USE_IPv6)],
    [AC_MSG_RESULT([no])]
)

# Disable use of libwrap (TCP wrappers)
# it should be the last check!
AC_MSG_CHECKING([whether to disable TCP wrappers library support])
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       Disable TCP wrappers library support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([no])
                AC_DEFINE(HAVE_LIBWRAP)
                ;;
            no) AC_MSG_RESULT([yes])
                ;;
            *) AC_MSG_ERROR([bad value ${enableval}])
                ;;
        esac
    ],
    [
        AC_MSG_RESULT([autodetecting])
        AC_MSG_CHECKING([for hosts_access in -lwrap])
        saved_LIBS="$LIBS"
        LIBS="$saved_LIBS -lwrap"
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [[int hosts_access(); int allow_severity, deny_severity;]],
                [[hosts_access()]]
            )],
            [AC_MSG_RESULT([yes]); AC_DEFINE(HAVE_LIBWRAP)],
            [AC_MSG_RESULT([no]); LIBS="$saved_LIBS"]
        )
    ]
)

# FIPS Mode
AC_MSG_CHECKING([whether to enable FIPS mode support])
AC_ARG_ENABLE(fips,
[  --enable-fips           Enable OpenSSL FIPS mode],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                AC_DEFINE(USE_FIPS)
                ;;
            no) AC_MSG_RESULT([no])
                ;;
            *) AC_MSG_ERROR([bad value ${enableval}])
                ;;
        esac
    ],
    [
        AC_MSG_RESULT([autodetecting])
        AC_MSG_CHECKING([for FIPS_mode_set])
        INCLUDES="=l$ssldir/include"
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM(
                [[#include <openssl/fips.h>]],
                [[FIPS_mode_set(1);]],
            )],
            [AC_MSG_RESULT([yes])
                AC_DEFINE(USE_FIPS)
            ], [
                AC_MSG_RESULT([no])
            ]
        )
    ]
)

AC_MSG_NOTICE([**************************************** write the results])
AC_CONFIG_FILES([Makefile src/Makefile src/stunnel3 doc/Makefile tools/Makefile tools/stunnel.conf-sample tools/stunnel.init])
AC_OUTPUT

AC_MSG_NOTICE([**************************************** success])
# End of configure.ac
