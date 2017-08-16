#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ppp], [0.1], [562837353@qq.com])
AM_INIT_AUTOMAKE(ppp, 0.1)


m4_include([m4/ocaml.m4])


AC_CONFIG_SRCDIR([src/clib/pcap.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_RANLIB

# Checks for programs.
AC_PROG_CC
# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_open_live,,
		   [AC_MSG_ERROR("lib `pcap' not installed")])

# Checks for header files.
AC_CHECK_HEADERS([pcap.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CONFIG_FILES([Makefile
		 src/Makefile
                 src/clib/Makefile
		 src/parser/Makefile])

AC_OUTPUT
