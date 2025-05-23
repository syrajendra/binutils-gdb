## Process this file with automake to generate Makefile.in
#
#   Copyright (C) 2021-2025 Free Software Foundation, Inc.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING3.  If not see
# <http://www.gnu.org/licenses/>.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I . -I .. -I ../.. 

CCSOURCES = \
	Application.cc \
	BaseMetric.cc \
	BaseMetricTreeNode.cc \
	CallStack.cc \
	CatchOutOfMemory.cc \
	ClassFile.cc \
	Command.cc \
	CompCom.cc \
	DataObject.cc \
	DataSpace.cc \
	Data_window.cc \
	DataStream.cc \
	DbeApplication.cc \
	DbeFile.cc \
	DbeJarFile.cc \
	DbeLock.cc \
	DbeSession.cc \
	DbeThread.cc \
	DbeView.cc \
	DerivedMetrics.cc \
	Disasm.cc \
	Dwarf.cc \
	DwarfLib.cc \
	Elf.cc \
	Emsg.cc \
	Experiment.cc \
	Exp_Layout.cc \
	ExpGroup.cc \
	Expression.cc \
	FileData.cc \
	Filter.cc \
	FilterSet.cc \
	Function.cc \
	HeapMap.cc \
	HeapData.cc \
	HeapActivity.cc \
	Hist_data.cc \
	IndexObject.cc \
	IOActivity.cc \
	LoadObject.cc \
	MachineModel.cc \
	MemObject.cc \
	MemorySpace.cc \
	Metric.cc \
	MetricList.cc \
	Module.cc \
	Ovw_data.cc \
	PRBTree.cc \
	PathTree.cc \
	PreviewExp.cc \
	Print.cc \
	SAXParserFactory.cc \
	Sample.cc \
	Settings.cc \
	SourceFile.cc \
	Stabs.cc \
	Stats_data.cc \
	StringBuilder.cc \
	Symbol.cc \
	Table.cc \
	QLParser.tab.cc \
	dbe_collctrl.cc \
	i18n.cc \
	parse.cc \
	UserLabel.cc \
	util.cc \
	Dbe.cc \
	$(NULL)

CSOURCES = \
	dbe_hwcdrv.c \
	dbe_hwcfuncs.c \
	dbe_hwctable.c \
	gethrtime.c \
	$(NULL)

LIBGPROFNG = libgprofng.la

# This is where we get zlib from.  zlibdir is -L../zlib and zlibinc is
# -I../zlib, unless we were configured with --with-system-zlib, in which
# case both are empty.
ZLIB = @zlibdir@ -lz
ZLIBINC = @zlibinc@

LOCALEDIR = @localedir@
SYSCONFDIR = @sysconfdir@

AM_CPPFLAGS = $(GPROFNG_CPPFLAGS) -DLOCALEDIR=\"$(LOCALEDIR)\" \
	-DSYSCONFDIR=\"$(SYSCONFDIR)\" -DLIBDIR=\"$(libdir)\" \
	-I.. -I$(srcdir) \
	-I$(srcdir)/../common \
	-I$(srcdir)/../../include -I$(srcdir)/../../opcodes \
	-I../../bfd -I$(srcdir)/../../bfd $(ZLIBINC)
AM_CFLAGS = $(GPROFNG_CFLAGS) $(PTHREAD_CFLAGS) \
	$(GPROFNG_NO_SWITCH_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)

# bison generates two files QLParser.tab.cc, QLParser.tab.hh.
# we don't know which file will be newer.
# Make QLParser.tab.cc always newer than QLParser.tab.hh.
QLParser.tab.hh: QLParser.yy
	if test "$(BISON)" = ":"; then \
	  echo "fatal: Building gprofng requires bison 3.0.4 or later."; \
	  exit 1; \
	fi; \
	$(BISON) $^

QLParser.tab.cc: QLParser.tab.hh
	touch $@

BUILT_SOURCES = QLParser.tab.cc QLParser.tab.hh
EXTRA_DIST = QLParser.tab.cc QLParser.tab.hh QLParser.yy

# info and diststuff are needed for src-release.sh:
info: $(BUILT_SOURCES)
diststuff: info

lib_LTLIBRARIES = $(LIBGPROFNG)
libgprofng_la_SOURCES = $(CCSOURCES) $(CSOURCES)
libgprofng_la_LDFLAGS = -version-info 0:0:0

# Pass -lpthread instead of $(PTHREAD_LIBS) due to $(PTHREAD_LIBS) being empty
# when -nostdlib is passed to libtool.
# See bug 29364 - libgprofng.so: needs to link against -pthread
libgprofng_la_LIBADD = $(top_builddir)/../opcodes/libopcodes.la \
	$(top_builddir)/../bfd/libbfd.la \
	$(GPROFNG_LIBADD) \
	-lpthread -ldl

dbedir = $(SYSCONFDIR)
dbe_DATA = $(srcdir)/gprofng.rc


bin_PROGRAMS = gprofng-archive gprofng-collect-app gprofng \
	gprofng-display-text gprofng-display-src

gprofng_archive_SOURCES = gp-archive.cc ArchiveExp.cc
gprofng_archive_LDADD = $(LIBGPROFNG) $(CLOCK_GETTIME_LINK) $(ZLIB)

gprofng_collect_app_SOURCES = gp-collect-app.cc checks.cc envsets.cc count.cc
gprofng_collect_app_LDADD = $(LIBGPROFNG) $(CLOCK_GETTIME_LINK) $(ZLIB)

gprofng_SOURCES = gprofng.cc
gprofng_LDADD = $(LIBGPROFNG) $(CLOCK_GETTIME_LINK) $(ZLIB)

gprofng_display_src_SOURCES = gp-display-src.cc
gprofng_display_src_LDADD = $(LIBGPROFNG) $(CLOCK_GETTIME_LINK) $(ZLIB)

gprofng_display_text_SOURCES = gp-display-text.cc ipc.cc ipcio.cc
gprofng_display_text_LDADD = $(LIBGPROFNG) $(CLOCK_GETTIME_LINK) $(ZLIB)

# Distribution involves building the binaries to generate the manpage,
# so ensure that the necessary libraries are built at dist time.
dist-hook: $(LIBGPROFNG)

$(srcdir)/DbeSession.cc: QLParser.tab.hh

.PHONY: install-exec-local
install-exec-local:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	for i in gp-{archive,collect-app,display-html,display-src,display-text}; do \
		oldname=`echo $$i | sed '$(transform)'`; \
		rm -f $(DESTDIR)$(bindir)/$$oldname ; \
		ln -s `echo $$oldname | sed 's&gp-&gprofng-&'` $(DESTDIR)$(bindir)/$$oldname; \
	done
