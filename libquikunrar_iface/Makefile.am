#
#  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@quikav.net>
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

AM_CPPFLAGS = -I$(top_srcdir) $(LTDLINCL)
AM_CFLAGS = @WERR_CFLAGS@
EXTRA_DIST =
EXTRA_DIST += @top_srcdir@/libquikunrar/libquikunrar.map @top_srcdir@/libquikunrar_iface/libquikunrar_iface.map
if ENABLE_UNRAR

libquikunrar_la_LDFLAGS = @TH_SAFE@ -version-info @LIBQUIKAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libquikunrar_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libquikunrar/libquikunrar.map
endif

libquikunrar_la_SOURCES = \
	../libquikunrar/unrar15.c \
	../libquikunrar/unrar20.h \
	../libquikunrar/unrar.h \
	../libquikunrar/unrar15.h \
	../libquikunrar/unrar.c \
	../libquikunrar/unrar20.c \
	../libquikunrar/unrarcmd.h \
	../libquikunrar/unrarfilter.h \
	../libquikunrar/unrarppm.c \
	../libquikunrar/unrarvm.c \
	../libquikunrar/unrarcmd.c \
	../libquikunrar/unrarfilter.c \
	../libquikunrar/unrar.h \
	../libquikunrar/unrarppm.h \
	../libquikunrar/unrarvm.h \
	../libquikunrar/unrarhlp.c \
	../libquikunrar/unrarhlp.h

lib_LTLIBRARIES = libquikunrar.la
libquikunrar_iface_la_LIBADD = libquikunrar.la
libquikunrar_iface_la_LDFLAGS = -module @TH_SAFE@ -version-info @LIBQUIKAV_VERSION@ -no-undefined

if VERSIONSCRIPT
libquikunrar_iface_la_LDFLAGS += -Wl,@VERSIONSCRIPTFLAG@,@top_srcdir@/libquikunrar_iface/libquikunrar_iface.map
endif

libquikunrar_iface_la_SOURCES = \
	../libquikunrar_iface/unrar_iface.c \
	../libquikunrar_iface/unrar_iface.h

lib_LTLIBRARIES += libquikunrar_iface.la
endif
