bin_PROGRAMS = quikbc
quikbc_SOURCES = \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    bcrun.c

AM_CFLAGS=@WERR_CFLAGS@ @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libquikav
LIBS = $(top_builddir)/libquikav/libquikav.la @THREAD_LIBS@
CLEANFILES=*.gcda *.gcno
