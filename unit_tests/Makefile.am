SPLIT_DIR=$(top_srcdir)/unit_tests/.split
FILES = quik-phish-exe

check_unit_vg.sh: $(FILES)
check2_quikd.sh: $(FILES)
check3_quikd.sh: $(FILES)
check4_quikd.sh: $(FILES)
check5_quikd_vg.sh: $(FILES)
check6_quikd_vg.sh: $(FILES)
check7_quikd_vg.sh: $(FILES)
check8_quikd_hg.sh: $(FILES)
check9_quikd_hg.sh: $(FILES)
check10_quikd_hg.sh: $(FILES)

$(FILES) :
	cat $(SPLIT_DIR)/split.$@aa $(SPLIT_DIR)/split.$@ab > $@


programs = check_quikav
scripts = check_freshquik.sh check_sigtool.sh check_unit_vg.sh check1_quikscan.sh check2_quikd.sh check3_quikd.sh check4_quikd.sh\
	  check5_quikd_vg.sh check6_quikd_vg.sh check7_quikd_hg.sh check8_quikd_hg.sh check9_quikscan_vg.sh
utils = check_fpu_endian
TESTS_ENVIRONMENT=export abs_srcdir=$(abs_srcdir) AWK=$(AWK);
if ENABLE_UNRAR
else
TESTS_ENVIRONMENT += export unrar_disabled=1;
endif
TESTS = $(programs) $(scripts)
check_PROGRAMS = $(programs) check_quikd $(utils)
check_SCRIPTS = $(scripts)

AM_CFLAGS=@WERR_CFLAGS@
if HAVE_LIBCHECK
check_quikav_SOURCES = check_quikav.c checks.h checks_common.h $(top_builddir)/libquikav/quikav.h\
		       check_jsnorm.c check_str.c check_regex.c\
		       check_disasm.c check_uniq.c check_matchers.c\
		       check_htmlnorm.c check_bytecode.c
check_quikav_CPPFLAGS = -I$(top_srcdir) @CHECK_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -DSRCDIR=\"$(abs_srcdir)\" -DOBJDIR=\"$(abs_builddir)\"
check_quikav_LDADD = $(top_builddir)/libquikav/libquikav.la @THREAD_LIBS@ @CHECK_LIBS@
check_quikav_LDFLAGS = $(XML_LIBS)
check_quikav_CFLAGS = $(AM_CFLAGS) $(XML_CPPFLAGS)
check_quikd_SOURCES = check_quikd.c checks_common.h
check_quikd_CPPFLAGS = -I$(top_srcdir) @CHECK_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -DSRCDIR=\"$(abs_srcdir)\" -DBUILDDIR=\"$(abs_builddir)\"
check_quikd_LDADD = @CHECK_LIBS@ @QUIKD_LIBS@
else
check_quikd_SOURCES = check_quikav_skip.c
check_quikav_SOURCES = check_quikav_skip.c
endif

check_fpu_endian_SOURCES = check_fpu_endian.c
check_fpu_endian_CPPFLAGS = -I$(top_srcdir) @CHECK_CPPFLAGS@ @JSON_CPPFLAGS@ @PCRE_CPPFLAGS@ -DSRCDIR=\"$(abs_srcdir)\" -DOBJDIR=\"$(abs_builddir)\"
check_fpu_endian_LDADD = $(top_builddir)/libquikav/libquikav.la

check_quikav.c: $(top_builddir)/test/quik.exe quikav.hdb
check_quikd.sh: $(top_builddir)/test/quik.exe check_quikd
check_quikscan.sh: $(top_builddir)/test/quik.exe

quikav.hdb: input/quikav.hdb
	cp $< $@

$(top_builddir)/test/quik.exe:
	(cd $(top_builddir)/test && $(MAKE))

quick-check:
	VALGRIND=no LIBEFENCE=no LIBDUMA=no $(MAKE) check

CLEANFILES=lcov.out *.gcno *.gcda *.log $(FILES) test-stderr.log quikscan.log accdenied quikav.hdb $(utils)
EXTRA_DIST=.split $(srcdir)/*.ref input test-freshquik.conf valgrind.supp virusaction-test.sh $(scripts) preload_run.sh check_common.sh
if ENABLE_COVERAGE
LCOV_OUTPUT = lcov.out
LCOV_HTML = lcov_html
LCOV_LCOV = @LCOV@
LCOV_GCOV = @GCOV@
LCOV_GENHTML = @GENHTML@
lcov: $(LCOV_HTML)
DIRECTORIES=--directory . --directory ../libquikav --directory ../quikd --directory ../freshquik --directory ../sigtool --directory ../quikscan --directory ../quikdscan
.libs/check_quikav.gcda: $(TESTS)
	$(LCOV_LCOV) $(DIRECTORIES) --zerocounters
	@$(MAKE) check VALGRIND= LIBDUMA=no LIBEFENCE=no

$(LCOV_OUTPUT): .libs/check_quikav.gcda
	$(LCOV_LCOV) --capture $(DIRECTORIES) --output-file $@

$(LCOV_HTML): $(LCOV_OUTPUT)
	-$(RM) -r $@
	LANG=C $(LCOV_GENHTML) --output-directory $@ --title "QuikAV Code Coverage" --show-details $<
	@echo "Open `pwd`/$(LCOV_HTML)/index.html in a browser."

clean-local: lcov-clean
.PHONY: lcov-clean
lcov-clean:
	-$(RM) -r $(LCOV_HTML) $(LCOV_OUTPUT)
	$(LCOV_LCOV) $(DIRECTORIES) --zerocounters
else

lcov:
	@echo "Coverage information gathering is not enabled in this build"
	@echo "Use ./configure --enable-coverage to enable it"
	@exit 1
endif
