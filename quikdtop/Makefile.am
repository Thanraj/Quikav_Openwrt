if HAVE_CURSES
bin_PROGRAMS = quikdtop
man_MANS = $(top_builddir)/docs/man/quikdtop.1
quikdtop_SOURCES = \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    quikdtop.c

AM_CFLAGS=@WERR_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/shared -I$(top_srcdir)/libquikav @SSL_CPPFLAGS@ @CURSES_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
quikdtop_LDADD = @SSL_LDFLAGS@ @SSL_LIBS@ @CURSES_LIBS@ $(top_builddir)/libquikav/libquikav_internal_utils_nothreads.la
endif
DEFS = @DEFS@ -DCL_NOTHREADS -DCL_NOLIBQUIKAV
EXTRA_DIST = quikdtop.c
