AC_INIT(kgdb-main.c)
AC_CONFIG_HEADER(config.h:config.in)
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([../../config])

# Set the 'development' global.
. $srcdir/../../bfd/development.sh

AC_PROG_CC
AC_PROG_CXX

AC_USE_SYSTEM_EXTENSIONS
AM_PROG_CC_STDC
AM_PROG_INSTALL_STRIP

AC_GNU_SOURCE
AC_SYS_LARGEFILE

AC_CANONICAL_SYSTEM
AC_ARG_PROGRAM

AC_PROG_INSTALL
AC_CHECK_TOOL(AR, ar)
AC_PROG_RANLIB

AC_HEADER_STDC

ACX_NONCANONICAL_TARGET
ACX_NONCANONICAL_HOST

. ${srcdir}/configure.kgdb
KGDB_TARGET_OBJS=`get_kgdb_objs`

AS_IF([test -z "${KGDB_TARGET_OBJS}"],
  [AC_MSG_ERROR([configuration ${target} is unsupported.])])

AC_SUBST(KGDB_TARGET_OBJS)

GDB_SIM=`get_gdb_sim`
AC_SUBST(GDB_SIM)

KGDB_CFLAGS_EXTRA=`get_kgdb_cflags_extra`
AC_SUBST(KGDB_CFLAGS_EXTRA)

KGDB_HOST_LDFLAGS=`get_kgdb_host_ldflags`
AC_SUBST(KGDB_HOST_LDFLAGS)

GNULIB=../build-gnulib/import

# For Makefile dependencies.
GNULIB_STDINT_H=
if test x"$STDINT_H" != x; then
  GNULIB_STDINT_H=$GNULIB/$STDINT_H
fi
AC_SUBST(GNULIB_STDINT_H)

case "$host_alias" in
  *linux*) configure_libbsd="yes" ;;
  *) configure_libbsd="no" ;;
esac

if test "$configure_libbsd" = "yes"; then
  AC_CONFIG_SUBDIRS(libbsd)
  KGDB_SUBDIRS="libbsd"
fi

AC_SUBST(KGDB_SUBDIRS)

AC_CONFIG_FILES([Makefile],
[case x$CONFIG_HEADERS in
xconfig.h:config.in)
echo > stamp-h ;;
esac
])

AC_OUTPUT
