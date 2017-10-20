#
#  Copyright (C) 2003 - 2005 Tomasz Kojm <tkojm@quikav.net>
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
if HAVE_MILTER

sbin_PROGRAMS = quikav-milter

quikav_milter_SOURCES = \
    $(top_srcdir)/shared/optparser.c \
    $(top_srcdir)/shared/optparser.h \
    $(top_srcdir)/shared/output.c \
    $(top_srcdir)/shared/output.h \
    $(top_srcdir)/shared/getopt.c \
    $(top_srcdir)/shared/getopt.h \
    $(top_srcdir)/shared/misc.c \
    $(top_srcdir)/shared/misc.h \
    whitelist.c \
    whitelist.h \
    connpool.c \
    connpool.h \
    netcode.c \
    netcode.h \
    quikfi.c \
    quikfi.h \
    quikav-milter.c
man_MANS = $(top_builddir)/docs/man/quikav-milter.8
AM_CFLAGS=@WERR_CFLAGS_MILTER@

endif
endif

DEFS = @DEFS@ -DCL_NOLIBQUIKAV
LIBS = $(top_builddir)/libquikav/libquikav_internal_utils.la @QUIKAV_MILTER_LIBS@ @THREAD_LIBS@
AM_CPPFLAGS = -I$(top_srcdir)/quikd -I$(top_srcdir)/libquikav -I$(top_srcdir)/shared -I$(top_srcdir) @SSL_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@
CLEANFILES=*.gcda *.gcno
