#
#  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@quikav.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

if BUILD_QUIKD

bin_PROGRAMS = quikdscan

quikdscan_SOURCES = \
    $(top_srcdir)/shared/output.c \
    $(top_srcdir)/shared/output.h \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/actions.c \
    $(top_srcdir)/shared/actions.h \
    $(top_srcdir)/shared/quikdcom.c \
    $(top_srcdir)/shared/quikdcom.h \
    quikdscan.c \
    proto.c \
    proto.h \
    client.c \
    client.h

AM_CFLAGS=@WERR_CFLAGS@
endif


DEFS = @DEFS@ -DCL_NOTHREADS -DCL_NOLIBQUIKAV
AM_CPPFLAGS = @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -I$(top_srcdir) -I$(top_srcdir)/quikscan -I$(top_srcdir)/shared -I$(top_srcdir)/libquikav @SSL_CPPFLAGS@ @QUIKDSCAN_CPPFLAGS@
LIBS = $(top_builddir)/libquikav/libquikav_internal_utils_nothreads.la  @QUIKDSCAN_LIBS@

AM_INSTALLCHECK_STD_OPTIONS_EXEMPT=quikdscan$(EXEEXT)
CLEANFILES=*.gcda *.gcno
