# Process this file with autoconf to produce a configure script.

AC_INIT([stunnel],[5.31])
AC_MSG_NOTICE([**************************************** initialization])
AC_CONFIG_AUX_DIR(auto)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_SRCDIR([src/stunnel.c])
AM_INIT_AUTOMAKE

AM_CONDITIONAL([AUTHOR_TESTS], [test -d ".git"])
AC_CANONICAL_HOST
AC_SUBST([host])
AC_DEFINE_UNQUOTED([HOST], ["$host"], [Host description])
define([esc], [`echo ]$1[ | tr abcdefghijklmnopqrstuvwxyz.- ABCDEFGHIJKLMNOPQRSTUVWXYZ__ | tr -dc ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_`])
AC_DEFINE_UNQUOTED(esc(CPU_$host_cpu))
AC_DEFINE_UNQUOTED(esc(VENDOR_$host_vendor))
AC_DEFINE_UNQUOTED(esc(OS_$host_os))

case "$host_os" in
*darwin*)
    # OSX does not declare ucontext without _XOPEN_SOURCE
    AC_DEFINE([_XOPEN_SOURCE], [500], [Use X/Open 5 with POSIX 1995])
    # OSX does not declare chroot() without _DARWIN_C_SOURCE
    AC_DEFINE([_DARWIN_C_SOURCE], [1], [Use Darwin source])
    ;;
*)
    AC_DEFINE([_GNU_SOURCE], [1], [Use GNU source])
    ;;
esac

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
# silent build by default
ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_MSG_NOTICE([**************************************** thread model])
# thread detection should be done first, as it may change the CC variable

AC_ARG_WITH(threads,
[  --with-threads=model    select threading model (ucontext/pthread/fork)],
[
    case "$withval" in
        ucontext)
            AC_MSG_NOTICE([UCONTEXT mode selected])
            AC_DEFINE([USE_UCONTEXT], [1], [Define to 1 to select UCONTEXT mode])
            ;;
        pthread)
            AC_MSG_NOTICE([PTHREAD mode selected])
            AX_PTHREAD()
            LIBS="$PTHREAD_LIBS $LIBS"
            CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
            CC="$PTHREAD_CC"
            AC_DEFINE([USE_PTHREAD], [1], [Define to 1 to select PTHREAD mode])
            ;;
        fork)
            AC_MSG_NOTICE([FORK mode selected])
            AC_DEFINE([USE_FORK], [1], [Define to 1 to select FORK mode])
            ;;
        *)
            AC_MSG_ERROR([Unknown thread model \"${withval}\"])
            ;;
    esac
], [
    # do not attempt to autodetect UCONTEXT threading
    AX_PTHREAD([
        AC_MSG_NOTICE([PTHREAD thread model detected])
        LIBS="$PTHREAD_LIBS $LIBS"
        CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
        CC="$PTHREAD_CC"
        AC_DEFINE([USE_PTHREAD], [1], [Define to 1 to select PTHREAD mode])
    ], [
        AC_MSG_NOTICE([FORK thread model detected])
        AC_DEFINE([USE_FORK], [1], [Define to 1 to select FORK mode])
    ])
])

AC_MSG_NOTICE([**************************************** compiler/linker flags])
if test "$GCC" = yes; then
    AX_APPEND_COMPILE_FLAGS([-Wall])
    AX_APPEND_COMPILE_FLAGS([-Wextra])
    AX_APPEND_COMPILE_FLAGS([-Wpedantic])
    AX_APPEND_COMPILE_FLAGS([-Wformat=2])
    AX_APPEND_COMPILE_FLAGS([-Wconversion])
    AX_APPEND_COMPILE_FLAGS([-Wno-long-long])
    AX_APPEND_COMPILE_FLAGS([-Wno-deprecated-declarations])
    AX_APPEND_COMPILE_FLAGS([-fPIE])
    case "${host}" in
        avr-*.* | powerpc-*-aix* | rl78-*.* | visium-*.*)
            ;;
        *)
            AX_APPEND_COMPILE_FLAGS([-fstack-protector])
            ;;
    esac
    AX_APPEND_LINK_FLAGS([-fPIE -pie])
    AX_APPEND_LINK_FLAGS([-Wl,-z,relro])
    AX_APPEND_LINK_FLAGS([-Wl,-z,now])
    AX_APPEND_LINK_FLAGS([-Wl,-z,noexecstack])
fi
AX_APPEND_COMPILE_FLAGS([-D_FORTIFY_SOURCE=2])

AC_MSG_NOTICE([**************************************** libtool])
LT_INIT([disable-static])
AC_SUBST([LIBTOOL_DEPS])

AC_MSG_NOTICE([**************************************** types])
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_MSG_CHECKING([for socklen_t])
AC_EGREP_HEADER(socklen_t, sys/socket.h,
    AC_MSG_RESULT([yes]),
    AC_MSG_RESULT([no (defined as int)])
    AC_DEFINE([socklen_t], [int], [Type of socklen_t]))
AC_CHECK_TYPES([struct sockaddr_un], [], [], [#include <sys/un.h>])
AC_CHECK_TYPES([struct addrinfo], [], [], [#include <netdb.h>])

AC_MSG_NOTICE([**************************************** PTY device files])
if test "x$cross_compiling" = "xno"; then
    AC_CHECK_FILE("/dev/ptmx", AC_DEFINE([HAVE_DEV_PTMX], [1],
        [Define to 1 if you have '/dev/ptmx' device.]))
    AC_CHECK_FILE("/dev/ptc", AC_DEFINE([HAVE_DEV_PTS_AND_PTC], [1],
        [Define to 1 if you have '/dev/ptc' device.]))
else
    AC_MSG_WARN([cross-compilation: assuming /dev/ptmx and /dev/ptc are not available])
fi

AC_MSG_NOTICE([**************************************** entropy sources])

if test "x$cross_compiling" = "xno"; then
    AC_ARG_WITH(egd-socket,
        [  --with-egd-socket=FILE  Entropy Gathering Daemon socket path],
        [EGD_SOCKET="$withval"]
    )
    if test -n "$EGD_SOCKET"; then
        AC_DEFINE_UNQUOTED([EGD_SOCKET], ["$EGD_SOCKET"],
            [Entropy Gathering Daemon socket path])
    fi

    # Check for user-specified random device
    AC_ARG_WITH(random,
    [  --with-random=FILE      read randomness from file (default=/dev/urandom)],
        [RANDOM_FILE="$withval"],
        [
            # Check for random device
            AC_CHECK_FILE("/dev/urandom", RANDOM_FILE="/dev/urandom")
        ]
    )
    if test -n "$RANDOM_FILE"; then
        AC_SUBST([RANDOM_FILE])
        AC_DEFINE_UNQUOTED([RANDOM_FILE], ["$RANDOM_FILE"], [Random file path])
    fi
else
    AC_MSG_WARN([cross-compilation: assuming entropy sources are not available])
fi

AC_MSG_NOTICE([**************************************** default group])
DEFAULT_GROUP=nobody
if test "x$cross_compiling" = "xno"; then
    grep '^nogroup:' /etc/group >/dev/null && DEFAULT_GROUP=nogroup
else
    AC_MSG_WARN([cross-compilation: assuming nogroup is not available])
fi
AC_MSG_CHECKING([for default group])
AC_MSG_RESULT([$DEFAULT_GROUP])
AC_SUBST([DEFAULT_GROUP])

AC_MSG_NOTICE([**************************************** header files])
# AC_HEADER_DIRENT
# AC_HEADER_STDC
# AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdint.h inttypes.h malloc.h ucontext.h pthread.h poll.h \
    tcpd.h stropts.h grp.h unistd.h util.h libutil.h pty.h limits.h])
AC_CHECK_HEADERS([sys/types.h sys/select.h sys/poll.h sys/socket.h sys/un.h \
    sys/ioctl.h sys/filio.h sys/resource.h sys/uio.h sys/syscall.h])
AC_CHECK_HEADERS([linux/sched.h])
AC_CHECK_MEMBERS([struct msghdr.msg_control],
    [AC_DEFINE([HAVE_MSGHDR_MSG_CONTROL], [1],
    [Define to 1 if you have 'msghdr.msg_control' structure.])], [], [
AC_INCLUDES_DEFAULT
#include <sys/socket.h>
    ])
AC_CHECK_HEADERS([linux/netfilter_ipv4.h], , , 
    [
#include <limits.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <netdb.h>
    ])

AC_MSG_NOTICE([**************************************** libraries])
# Checks for standard libraries
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([yp_get_default_domain], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([openpty], [util])
# Checks for dynamic loader and zlib needed by OpenSSL
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([shl_load], [dld])
AC_SEARCH_LIBS([inflateEnd], [z])

# Add BeOS libraries
if test "x$host_os" = "xbeos"; then
    LIBS="$LIBS -lbe -lroot -lbind"
fi

AC_MSG_NOTICE([**************************************** library functions])
# safe string operations
AC_CHECK_FUNCS(snprintf vsnprintf)
# pseudoterminal
AC_CHECK_FUNCS(openpty _getpty)
# Unix
AC_CHECK_FUNCS(daemon waitpid wait4 setsid setgroups chroot realpath)
# limits
AC_CHECK_FUNCS(sysconf getrlimit)
# threads/reentrant functions
AC_CHECK_FUNCS(pthread_sigmask localtime_r)
# threads
AC_CHECK_FUNCS(getcontext __makecontext_v2)
# sockets
AC_CHECK_FUNCS(poll gethostbyname2 endhostent getnameinfo)
AC_MSG_CHECKING([for getaddrinfo])
case "$host_os" in
*androideabi*)
    # http://stackoverflow.com/questions/7818246/segmentation-fault-in-getaddrinfo
    AC_MSG_RESULT([no (buggy Android implementation)])
    ;;
*)
    # Tru64 UNIX has getaddrinfo() but has it renamed in libc as
    # something else so we must include <netdb.h> to get the
    # redefinition.
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [
AC_INCLUDES_DEFAULT
#include <sys/socket.h>
#include <netdb.h>
            ],
            [
getaddrinfo(NULL, NULL, NULL, NULL);
            ],)],
        [AC_MSG_RESULT([yes]); AC_DEFINE([HAVE_GETADDRINFO], [1], [Define to 1 if you have 'getaddrinfo' function.])],
        [AC_MSG_RESULT([no])])
    ;;
esac
# poll() is not recommended on Mac OS X <= 10.3 and broken on Mac OS X 10.4
AC_MSG_CHECKING([for broken poll() implementation])
case "$host_os" in
darwin[0-8].*)
    AC_MSG_RESULT([yes (poll() disabled)])
    AC_DEFINE([BROKEN_POLL], [1], [Define to 1 if you have a broken 'poll' implementation.])
    ;;
*)
    AC_MSG_RESULT([no])
    ;;
esac
# GNU extensions
AC_CHECK_FUNCS(pipe2 accept4)

AC_MSG_NOTICE([**************************************** optional features])
# Use IPv6?
AC_MSG_CHECKING([whether to enable IPv6 support])
AC_ARG_ENABLE(ipv6,
[  --disable-ipv6          disable IPv6 support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AC_DEFINE([USE_IPv6], [1],
                    [Define to 1 to enable IPv6 support])
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([bad value \"${enableval}\"])
                 ;;
        esac
    ], [
        AC_MSG_RESULT([yes (default)])
        AC_DEFINE([USE_IPv6], [1], [Define to 1 to enable IPv6 support])
    ], [
        AC_MSG_RESULT([no])
    ]
)

# FIPS Mode
AC_MSG_CHECKING([whether to enable FIPS support])
AC_ARG_ENABLE(fips,
[  --disable-fips          disable OpenSSL FIPS support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([no])
                 use_fips="yes"
                 AC_DEFINE([USE_FIPS], [1],
                    [Define to 1 to enable OpenSSL FIPS support])
                 ;;
            no)  AC_MSG_RESULT([no])
                 use_fips="no"
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        use_fips="auto"
        AC_MSG_RESULT([autodetecting])
    ]
)

# Disable systemd socket activation support
AC_MSG_CHECKING([whether to enable systemd socket activation support])
AC_ARG_ENABLE(systemd,
[  --disable-systemd       disable systemd socket activation support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AC_SEARCH_LIBS([sd_listen_fds], [systemd systemd-daemon])
                 AC_DEFINE([USE_SYSTEMD], [1],
                     [Define to 1 to enable systemd socket activation])
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([Bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        AC_MSG_RESULT([autodetecting])
        # the library name has changed to -lsystemd in systemd 209
        AC_SEARCH_LIBS([sd_listen_fds], [systemd systemd-daemon],
            [ AC_CHECK_HEADERS([systemd/sd-daemon.h], [
                AC_DEFINE([USE_SYSTEMD], [1],
                    [Define to 1 to enable systemd socket activation])
                AC_MSG_NOTICE([systemd support enabled])
            ], [
                AC_MSG_NOTICE([systemd header not found])
            ]) ], [
                AC_MSG_NOTICE([systemd library not found])
            ])
    ]
)

# Disable use of libwrap (TCP wrappers)
# it should be the last check!
AC_MSG_CHECKING([whether to enable TCP wrappers support])
AC_ARG_ENABLE(libwrap,
[  --disable-libwrap       disable TCP wrappers support],
    [
        case "$enableval" in
            yes) AC_MSG_RESULT([yes])
                 AC_DEFINE([USE_LIBWRAP], [1],
                     [Define to 1 to enable TCP wrappers support])
                 LIBS="$LIBS -lwrap"
                 ;;
            no)  AC_MSG_RESULT([no])
                 ;;
            *)   AC_MSG_RESULT([error])
                 AC_MSG_ERROR([Bad value \"${enableval}\"])
                 ;;
        esac
    ],
    [
        AC_MSG_RESULT([autodetecting])
        AC_MSG_CHECKING([for hosts_access in -lwrap])
        valid_LIBS="$LIBS"
        LIBS="$valid_LIBS -lwrap"
        AC_LINK_IFELSE(
            [
                AC_LANG_PROGRAM(
                    [int hosts_access(); int allow_severity, deny_severity;],
                    [hosts_access()])
            ], [
                AC_MSG_RESULT([yes]);
                AC_DEFINE([USE_LIBWRAP], [1],
                    [Define to 1 to enable TCP wrappers support])
                AC_MSG_NOTICE([libwrap support enabled])
            ], [
                AC_MSG_RESULT([no])
                LIBS="$valid_LIBS"
                AC_MSG_NOTICE([libwrap library not found])
            ]
        )
    ]
)

AC_MSG_NOTICE([**************************************** SSL])

AC_MSG_CHECKING([for compiler sysroot])
if test "x$GCC" = "xyes"; then
    sysroot=`$CC --print-sysroot 2>/dev/null`
fi
if test -z "$sysroot" -o "x$sysroot" = "x/"; then
    sysroot=""
    AC_MSG_RESULT([/])
else
    AC_MSG_RESULT([$sysroot])
fi

check_ssl_dir() { :
    test -n "$1" -a -f "$1/include/openssl/ssl.h" && SSLDIR="$1"
}

find_ssl_dir() { :
    stunnel_prefix="$prefix"
    test "x$stunnel_prefix" = "xNONE" && stunnel_prefix=$ac_default_prefix
    for main_dir in "$stunnel_prefix" "/usr/local" "/usr/lib" "/usr/pkg" "/opt/local" "/opt" "/opt/csw" "/usr" ""; do
        for sub_dir in "/ssl" "/openssl" "/ossl" ""; do
            check_ssl_dir "$sysroot$main_dir$sub_dir" && return
        done
    done
    if test -x "/usr/bin/xcrun"; then
        sdk_path=`/usr/bin/xcrun --sdk macosx --show-sdk-path`
        check_ssl_dir "$sdk_path/usr" && return
    fi
    check_ssl_dir "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdk/MacOSX.sdk/usr"
}

SSLDIR=""
AC_MSG_CHECKING([for SSL directory])
AC_ARG_WITH(ssl,
[  --with-ssl=DIR          location of installed SSL libraries/include files],
    [check_ssl_dir "$withval"],
    [find_ssl_dir]
)
if test -z "$SSLDIR"; then
AC_MSG_RESULT([not found])
AC_MSG_ERROR([
Could not find your SSL library installation dir
Use --with-ssl option to fix this problem
]) 
fi
AC_MSG_RESULT([$SSLDIR])
AC_SUBST([SSLDIR])
AC_DEFINE_UNQUOTED([SSLDIR], ["$SSLDIR"], [SSL directory])

valid_CPPFLAGS="$CPPFLAGS"; CPPFLAGS="$CPPFLAGS -I$SSLDIR/include"
valid_LIBS="$LIBS"; LIBS="$LIBS -L$SSLDIR/lib64 -L$SSLDIR/lib -lssl -lcrypto"

if test "x$use_fips" = "xauto"; then
    AC_CHECK_FUNCS(FIPS_mode_set, [
        AC_DEFINE([USE_FIPS], [1], [Define to 1 to enable OpenSSL FIPS support])
        AC_MSG_NOTICE([FIPS support enabled])
    ], [
        AC_MSG_NOTICE([FIPS support not found])
    ])
fi

CPPFLAGS="$valid_CPPFLAGS"
LIBS="$valid_LIBS"

AC_MSG_NOTICE([**************************************** write the results])
AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile tools/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([**************************************** success])
# vim:ft=automake
# End of configure.ac
