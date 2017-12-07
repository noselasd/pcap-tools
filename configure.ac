AC_INIT([pcap-tools],
    0.1.0,
	[noselasd@fiane.mooo.com])

AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip 1.6])
#AC_CONFIG_TESTDIR(tests)

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P
AC_PROG_CC
AC_PROG_INSTALL
#LT_INIT([pic-only])

AC_CONFIG_MACRO_DIR([m4])

dnl checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(execinfo.h sys/select.h sys/socket.h syslog.h ctype.h)
AC_SYS_LARGEFILE

AC_ARG_ENABLE(doxygen,
    [AS_HELP_STRING(
        [--enable-doxygen],
        [Enable generating doxygen docs]
    )],
    [GEN_DOXYGEN=$enableval], [GEN_DOXYGEN="no"])

AC_PATH_PROG(DOXYGEN,doxygen,false)
AM_CONDITIONAL(HAVE_DOXYGEN, test $DOXYGEN != false && test x"$GEN_DOXYGEN" != x"no")

dnl Checks for typedefs, structures and compiler characteristics
AC_ARG_WITH([pcap-config],
    AC_HELP_STRING([--with-pcap-config=FILE], [Use given pcap-config]),
    [pcapcfg="$withval" ],
    [AC_PATH_PROG([pcapcfg], [pcap-config], [])])
if test x$pcapcfg = "x"; then
    AC_MSG_ERROR([pcap-config can not be found])
fi

dnl For systems without pcap-config
AC_ARG_VAR([PCAP_LIBS], [PCAP library files])
AC_ARG_VAR([PCAP_CFLAGS], [PCAP C compiler flags])

if test "x$ac_cv_env_PCAP_LIBS_set" != "xset"; then
    PCAP_LIBS=`$pcapcfg --libs`
fi

if test "x$ac_cv_env_PCAP_CFLAGS_set" != "xset"; then
    PCAP_CFLAGS=`$pcapcfg --cflags`
fi
AC_SUBST([PCAP_LIBS])
AC_SUBST([PCAP_CFLAGS])



#saved_CFLAGS="$CFLAGS"
#CFLAGS="$CFLAGS -fvisibility=hidden "
#AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
#AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
#      [ AC_MSG_RESULT([yes])
#        SYMBOL_VISIBILITY="-fvisibility=hidden"],
#        AC_MSG_RESULT([no]))
#CFLAGS="$saved_CFLAGS"
#AC_SUBST(SYMBOL_VISIBILITY)

dnl Generate the output
AC_CONFIG_HEADER(config.h)

AC_OUTPUT(
	Makefile
	src/Makefile
    )
