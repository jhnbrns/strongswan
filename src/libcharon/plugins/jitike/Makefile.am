AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libcharon/plugins/ha \
	-I$(top_srcdir)/src/libcharon/redis \
	-I/opt/src/cloud-vpn-protobuf/esp \
	-I/opt/src/cloud-vpn-protobuf/ike \
	-DIPSEC_PIDDIR=\"${piddir}\"

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-jitike.la
else
plugin_LTLIBRARIES = libstrongswan-jitike.la
endif

libstrongswan_jitike_la_SOURCES = \
  jitike_crypto.h jitike_crypto.c \
  jitike_plugin.h jitike_plugin.c \
  jitike_message.h jitike_message.c \
  jitike_redis.h jitike_redis.c \
  jitike_redis_sentinel.h jitike_redis_sentinel.c \
  jitike_async_job.h jitike_async_job.c \
  jitike_del_job.h jitike_del_job.c \
  jitike_spi_generator.h jitike_spi_generator.c \
  jitike_ipsec.h jitike_ipsec.c \
  jitike_db.h \
  jitike_hiredis.h \
  esp.pb-c.c
libstrongswan_jitike_la_LIBADD = -l:libhiredis.a -lprotobuf-c -lprotobuf -levent
libstrongswan_jitike_la_LDFLAGS = -module -avoid-version

TESTS = libstrongswan_jitike_tests

check_PROGRAMS = $(TESTS)

libstrongswan_jitike_tests_SOURCES = \
	suites/test_jitike_crypto.c \
	jitike_crypto.c \
	tests.h tests.c

libstrongswan_jitike_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	@COVERAGE_CFLAGS@

libstrongswan_jitike_tests_LDFLAGS = @COVERAGE_LDFLAGS@
libstrongswan_jitike_tests_LDADD = \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	-lcrypto
