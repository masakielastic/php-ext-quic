PHP_ARG_ENABLE([quic], [whether to enable quic support],
  [AS_HELP_STRING([--enable-quic], [Enable QUIC support])],
  [yes])

if test "$PHP_QUIC" != "no"; then
  AC_PATH_PROG([PKG_CONFIG], [pkg-config], [no])

  QUIC_CFLAGS=""
  QUIC_LIBS=""

  if test "$PKG_CONFIG" != "no" && \
     $PKG_CONFIG --exists gnutls libngtcp2 libngtcp2_crypto_gnutls; then
    QUIC_CFLAGS=`$PKG_CONFIG --cflags gnutls libngtcp2 libngtcp2_crypto_gnutls`
    QUIC_LIBS=`$PKG_CONFIG --libs gnutls libngtcp2 libngtcp2_crypto_gnutls`
  else
    AC_MSG_WARN([pkg-config could not resolve gnutls/libngtcp2; using linker fallback])

    AC_CHECK_HEADER([gnutls/gnutls.h], [],
      [AC_MSG_ERROR([Cannot find gnutls headers])])
    AC_CHECK_HEADER([ngtcp2/ngtcp2.h], [],
      [AC_MSG_ERROR([Cannot find ngtcp2 headers])])
    AC_CHECK_HEADER([ngtcp2/ngtcp2_crypto_gnutls.h], [],
      [AC_MSG_ERROR([Cannot find ngtcp2 GnuTLS crypto headers])])

    AC_CHECK_LIB([gnutls], [gnutls_check_version], [],
      [AC_MSG_ERROR([Cannot find libgnutls])])
    AC_CHECK_LIB([ngtcp2], [ngtcp2_conn_get_expiry], [],
      [AC_MSG_ERROR([Cannot find libngtcp2])])
    AC_CHECK_LIB([ngtcp2_crypto_gnutls],
      [ngtcp2_crypto_gnutls_configure_client_session], [],
      [AC_MSG_ERROR([Cannot find libngtcp2_crypto_gnutls])],
      [-lngtcp2 -lgnutls])

    QUIC_LIBS="-lngtcp2_crypto_gnutls -lngtcp2 -lgnutls"
  fi

  PHP_EVAL_INCLINE([$QUIC_CFLAGS])
  PHP_EVAL_LIBLINE([$QUIC_LIBS], [QUIC_SHARED_LIBADD])

  PHP_NEW_EXTENSION([quic],
    [quic.c quic_client.c quic_server.c quic_stream.c],
    [$ext_shared],, [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])

  PHP_SUBST([QUIC_SHARED_LIBADD])
fi
