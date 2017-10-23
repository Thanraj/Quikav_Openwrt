#!/bin/sh

# Solaris's /bin/sh is not a POSIX shell, and
# it quits when cd fails, even if it is followed by a ||
# So enable -e only on POSIX shells
(cd /nonexistentdir 2>/dev/null || true) && set -e

WRAPPER=${WRAPPER-}
TOP=`pwd`/..
QUIKSCAN=$TOP/quikscan/quikscan
QUIKD=$TOP/quikd/quikd
CHECK_QUIKD=$TOP/unit_tests/check_quikd
QUIKDSCAN=$TOP/quikdscan/quikdscan
TESTFILES=$TOP/test/quik*
NFILES=`ls -1 $TESTFILES | wc -l`
#CHECK_FPU_ENDIAN=$TOP/unit_tests/.libs/lt-check_fpu_endian
CHECK_FPU_ENDIAN=$TOP/unit_tests/check_fpu_endian

killquikd() {
    test -f quikd-test.pid &&
    pid=`cat quikd-test.pid 2>/dev/null` &&
    test -n "$pid" &&
    kill -0 $pid 2>/dev/null &&
    kill $pid 2>/dev/null &&
    kill -0 $pid 2>/dev/null &&
    sleep 1 &&
    kill -0 $pid 2>/dev/null &&
    sleep 9 &&
    kill -0 $pid 2>/dev/null &&
    echo "Killing stuck quikd!" &&
    kill -KILL $pid && exit 109 || true
}

error()
{
	echo >&2
	echo "***" >&2
	echo "*** $1" >&2
	echo "***" >&2
}

die()
{
	error "$1"
	test -f valgrind.log && cat valgrind.log || true
	killquikd
	exit 42
}

# Setup test directory to avoid temporary and output file clashes
test_start() {
    ulimit -t 120 || true; ulimit -d 1024000 || true;
    ulimit -v 1024000 || true;
    (cd test-$1 2>/dev/null && killquikd || true)
    rm -rf test-$1
    mkdir test-$1
    cd test-$1
    mkdir test-db
    cat <<EOF >test-db/test.hdb
aa15bcf478d165efd2065190eb473bcb:544:QuikAV-Test-File
EOF
    port=331$1
    tries=0
    while nc -z localhost $port 2>/dev/null
	do rand=` ( echo $$ ; time ps 2>&1 ; date ) | cksum | cut -f1 -d" " `
	port=1`expr 100 + \( $rand % 899 \)`$1
	[ $tries -gt 100 ] && echo Giving up, too many ports open && exit 1
	tries=`expr $tries + 1`
    done
    cat <<EOF >test-quikd.conf
LogFile `pwd`/quikd-test.log
LogFileMaxSize 0
LogTime yes
Debug yes
LogClean yes
LogVerbose yes
PidFile `pwd`/quikd-test.pid
DatabaseDirectory `pwd`/test-db
LocalSocket quikd-test.socket
TCPAddr 127.0.0.1
# using different port here to avoid conflicts with system quikd daemon
TCPSocket $port
ExitOnOOM yes
DetectPUA yes
ScanPDF yes
CommandReadTimeout 1
MaxQueue 800
MaxConnectionQueueLength 1024
EOF
}

# arg1: expected exitcode
test_run() {
   expected=$1
   shift
   set +e
   $TOP/libtool --mode=execute $WRAPPER $*
   val=$?
   if test $val -ne $expected; then
       error "Failed to run $*, expected $expected exitcode, but was $val" >&2;
       return 0;
   fi
   set -e
   return 1;
}

# Run a test and return its exitcode
test_run_check() {
    set +e
    $TOP/libtool --mode=execute $WRAPPER $*
    val=$?
    set -e
    return $?;
}

# test successfully finished, remove test dir
test_end() {
    killquikd
    cd ..
    test -f test-$1/valgrind.log && mv -f test-$1/valgrind.log valgrind$1.log
    rm -rf test-$1
}

scan_failed() {
    cat $1
    die "$2";
}

# ----------- valgrind wrapper 
init_valgrind() {
    test "x$VG" = "x1" || { echo "*** valgrind tests skipped by default, use 'make check VG=1' to activate"; exit 77; }
    VALGRIND=`which ${VALGRIND-valgrind}` || true
    VALGRIND_COMMON_FLAGS="-v --trace-children=yes --suppressions=$abs_srcdir/valgrind.supp --log-file=valgrind.log --error-exitcode=123 $GENSUPP"
    VALGRIND_FLAGS="$VALGRIND_COMMON_FLAGS --track-fds=yes --leak-check=full"
    VALGRIND_FLAGS_RACE="$VALGRIND_COMMON_FLAGS --tool=helgrind"
    export VALGRIND VALGRIND_COMMON_FLAGS VALGRIND_FLAGS VALGRIND_FLAGS_RACE
    test -n "$VALGRIND" || { echo "*** valgrind not found, skipping test"; exit 77; }
    test -x "$VALGRIND" || { echo "*** valgrind not executable, skipping test"; exit 77; }
}

init_helgrind() {
    init_valgrind
}

end_valgrind() {
    VLOG=valgrind$1.log
    NRUNS=`grep -a "ERROR SUMMARY" $VLOG | wc -l`
    if test $NRUNS -ne `grep -a "ERROR SUMMARY: 0 errors" $VLOG | wc -l` || 
	test `grep -a "FATAL:" $VLOG|wc -l` -ne 0; then
	cat $VLOG
	die "Valgrind tests failed"
    fi
}

# ----------- quikscan tests --------------------------------------------------------
test_quikscan() {
    test_start $1
    if test_run 1 $QUIKSCAN --gen-json --debug --quiet -dtest-db/test.hdb $TESTFILES --log=quikscan.log; then
	scan_failed quikscan.log "quikscan didn't detect all testfiles correctly"
    fi
    NINFECTED=`grep "Infected files" quikscan.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "$NFILES" -ne "0$NINFECTED"; then
	scan_failed quikscan.log "quikscan didn't detect all testfiles correctly"
    fi

    cat <<EOF >test-db/test.pdb
H:example.com
EOF
    if test_run 0 $QUIKSCAN --gen-json --quiet -dtest-db $abs_srcdir/input/phish-test-* --log=quikscan2.log; then
	cat quikscan2.log;
	die "Failed to run quikscan (phish-test)";
    fi

    if test_run 1 $QUIKSCAN --gen-json --quiet --phishing-ssl --phishing-cloak -dtest-db $abs_srcdir/input/phish-test-* --log=quikscan3.log; then
	cat quikscan3.log;
	die "Failed to run quikscan (phish-test2)";
    fi

    grep "phish-test-ssl: Heuristics.Phishing.Email.SSL-Spoof FOUND" quikscan3.log >/dev/null || die "phish-test1 failed";
    grep "phish-test-cloak: Heuristics.Phishing.Email.Cloaked.Null FOUND" quikscan3.log >/dev/null || die "phish-test2 failed";

    cat <<EOF >test-db/test.ign2
QuikAV-Test-File
EOF
    cat <<EOF >test-db/test.idb
EA0X-32x32x8:ea0x-grp1:ea0x-grp2:2046f030a42a07153f4120a0031600007000005e1617ef0000d21100cb090674150f880313970b0e7716116d01136216022500002f0a173700081a004a0e
IScab-16x16x8:iscab-grp1:iscab-grp2:107b3000168306015c20a0105b07060be0a0b11c050bea0706cb0a0bbb060b6f00017c06018301068109086b03046705081b000a270a002a000039002b17
EOF
    cat <<EOF >test-db/test.ldb
QuikAV-Test-Icon-EA0X;Engine:52-1000,Target:1,IconGroup1:ea0x-grp1,IconGroup2:*;(0);0:4d5a
QuikAV-Test-Icon-IScab;Engine:52-1000,Target:1,IconGroup2:iscab-grp2;(0);0:4d5a
EOF
    if test_run 1 $QUIKSCAN --gen-json --quiet -dtest-db $TESTFILES --log=quikscan4.log; then
	scan_failed quikscan4.log "quikscan didn't detect icons correctly"
    fi
    NINFECTED=`grep "Infected files" quikscan4.log | cut -f2 -d: | sed -e 's/ //g'`
    grep "quik.ea05.exe: QuikAV-Test-Icon-EA0X.UNOFFICIAL FOUND" quikscan4.log || die "icon-test1 failed"

    test_run_check $CHECK_FPU_ENDIAN
    if test $? -eq 3; then
        NEXPECT=3
    else
        grep "quik.ea06.exe: QuikAV-Test-Icon-EA0X.UNOFFICIAL FOUND" quikscan4.log || die "icon-test2 failed"
        NEXPECT=4
    fi
    grep "quik_IScab_ext.exe: QuikAV-Test-Icon-IScab.UNOFFICIAL FOUND" quikscan4.log || die "icon-test3 failed"
    grep "quik_IScab_int.exe: QuikAV-Test-Icon-IScab.UNOFFICIAL FOUND" quikscan4.log || die "icon-test4 failed"
    if test "x$NINFECTED" != "x$NEXPECT"; then
	scan_failed quikscan4.log "quikscan has detected spurious icons or whitelisting was not applied properly"
    fi

cat <<EOF >test-db/test.ldb
Quik-VI-Test:Target;Engine:52-255,Target:1;(0&1);VI:43006f006d00700061006e0079004e0061006d0065000000000063006f006d00700061006e007900;VI:500072006f0064007500630074004e0061006d0065000000000063006c0061006d00
EOF
    if test_run 1 $QUIKSCAN --gen-json --quiet -dtest-db/test.ldb $TESTFILES --log=quikscan5.log; then
	scan_failed quikscan5.log "quikscan didn't detect VI correctly"
    fi
    grep "quik_ISmsi_ext.exe: Quik-VI-Test:Target.UNOFFICIAL FOUND" quikscan5.log || die "VI-test1 failed"
    grep "quik_ISmsi_int.exe: Quik-VI-Test:Target.UNOFFICIAL FOUND" quikscan5.log || die "VI-test2 failed"
    NINFECTED=`grep "Infected files" quikscan5.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "x$NINFECTED" != x2; then
	scan_failed quikscan4.log "quikscan has detected spurious VI's"
    fi

cat <<EOF >test-db/test.yara
rule yara_at_offset {strings: \$tar_magic = { 75 73 74 61 72 } condition: \$tar_magic at 257}
EOF
    if test_run 1 $QUIKSCAN --gen-json --quiet -dtest-db/test.yara $TESTFILES --log=quikscan6.log; then
	scan_failed quikscan6.log "quikscan YARA at-offset test failed"
    fi
    grep "quik.tar.gz: YARA.yara_at_offset.UNOFFICIAL FOUND" quikscan6.log || die "YARA at-offset test1 failed"
    grep "quik_cache_emax.tgz: YARA.yara_at_offset.UNOFFICIAL FOUND" quikscan6.log || die "YARA at-offset test2 failed"
    NINFECTED=`grep "Infected files" quikscan6.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "x$NINFECTED" != x2; then
	scan_failed quikscan7.log "quikscan: unexpected YARA offset match."
    fi

cat <<EOF >test-db/test.yara
rule yara_in_range {strings: \$tar_magic = { 75 73 74 61 72 } condition: \$tar_magic in (200..300)}
EOF
    if test_run 1 $QUIKSCAN --gen-json --quiet -dtest-db/test.yara $TESTFILES --log=quikscan7.log; then
	scan_failed quikscan7.log "quikscan YARA in-range test failed"
    fi
    grep "quik.tar.gz: YARA.yara_in_range.UNOFFICIAL FOUND" quikscan7.log || die "YARA in-range test1 failed"
    grep "quik_cache_emax.tgz: YARA.yara_in_range.UNOFFICIAL FOUND" quikscan7.log || die "YARA in-range test2 failed"
    NINFECTED=`grep "Infected files" quikscan7.log | cut -f2 -d: | sed -e 's/ //g'`
    if test "x$NINFECTED" != x2; then
	scan_failed quikscan7.log "quikscan: unexpected YARA range match."
    fi

    test_end $1
}

# ----------- quikd tests --------------------------------------------------------
start_quikd()
{
    cp $abs_srcdir/input/daily.pdb test-db/daily.pdb
    if test_run 0 $QUIKD -c test-quikd.conf --help >quikd-test.log; then
	die "Failed to run quikd --help";
    fi
    grep "Quik AntiVirus Daemon" quikd-test.log >/dev/null || die "Wrong --help reply from quikd!";
    if test_run 0 $QUIKD -c test-quikd.conf >quikd-test.log 2>&1; then
	cat quikd-test.log
	die "Failed to run quikd";
    fi
}

run_quikdscan_fileonly() {
    rm -f quikdscan.log quikdscan-multiscan.log
    $QUIKDSCAN --version --config-file=test-quikd.conf | grep "^QuikAV" >/dev/null || die "quikdscan can't get version of quikd!";
    set +e
    $QUIKDSCAN --quiet --config-file=test-quikd.conf $* --log=quikdscan.log
    if test $? = 2; then
	die "Failed to run quikdscan!"
    fi
    $QUIKDSCAN --quiet --config-file=test-quikd.conf $* -m --log=quikdscan-multiscan.log
    if test $? = 2; then
	die "Failed to run quikdscan (multiscan)!"
    fi
    set -e
}

run_quikdscan() {
    run_quikdscan_fileonly $*
    rm -f quikdscan-fdpass.log quikdscan-multiscan-fdpass.log quikdscan-stream.log quikdscan-multiscan-stream.log
    set +e
    $QUIKDSCAN --quiet --config-file=test-quikd.conf $* --fdpass --log=quikdscan-fdpass.log
    if test $? = 2; then 
	die "Failed to run quikdscan (fdpass)!"
    fi
    $QUIKDSCAN --quiet --config-file=test-quikd.conf $* -m --fdpass --log=quikdscan-multiscan-fdpass.log
    if test $? = 2; then 
        die "Failed to run quikdscan (fdpass + multiscan)!"
    fi
    $QUIKDSCAN --quiet --config-file=test-quikd.conf $* --stream --log=quikdscan-stream.log
    if test $? = 2; then 
    	die "Failed to run quikdscan (instream)!"
    fi
    $QUIKDSCAN --quiet --config-file=test-quikd.conf $* -m --stream --log=quikdscan-multiscan-stream.log
    if test $? = 2; then 
	die "Failed to run quikdscan (instream + multiscan)!"
    fi
    set -e
}

run_reload_test()
{
	echo "QuikAV-RELOAD-Test" >reload-testfile
	run_quikdscan reload-testfile
	# it is not supposed to detect until we actually put the
	# signature there and reload!
	grep "QuikAV-RELOAD-TestFile" quikdscan.log >/dev/null 2>/dev/null && die "RELOAD test(1) failed!"
	echo "QuikAV-RELOAD-TestFile:0:0:436c616d41562d52454c4f41442d54657374" >test-db/new.ndb
	$QUIKDSCAN --reload --config-file=test-quikd.conf || die "quikdscan says reload failed!"
	run_quikdscan reload-testfile
	failed=0
	grep "QuikAV-RELOAD-TestFile" quikdscan.log >/dev/null 2>/dev/null || die "RELOAD test failed! (after reload)"
	grep "QuikAV-RELOAD-TestFile" quikdscan-multiscan.log >/dev/null 2>/dev/null || die "RELOAD test failed! (after reload, multiscan)"
}

run_quikdscan_fdpass() {
    set +e
    $QUIKDSCAN --quiet --fdpass --config-file=test-quikd.conf - <$1 --log=quikdscan.log
    if test $? = 2; then
    	die "Failed to run quikdscan (fdpass)!"
    fi
    set -e
}

test_quikd1() {
    test_start $1
    start_quikd
    # Test that all testfiles are detected
    run_quikdscan $TESTFILES
    NINFECTED=`grep "Infected files" quikdscan.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_MULTI=`grep "Infected files" quikdscan-multiscan.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_FDPASS=`grep "Infected files" quikdscan-fdpass.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_MULTI_FDPASS=`grep "Infected files" quikdscan-multiscan-fdpass.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_STREAM=`grep "Infected files" quikdscan-stream.log | cut -f2 -d:|sed -e 's/ //g'`
    NINFECTED_MULTI_STREAM=`grep "Infected files" quikdscan-multiscan-stream.log | cut -f2 -d:|sed -e 's/ //g'`
    if test "$NFILES" -ne "0$NINFECTED"; then
	scan_failed quikdscan.log "quikd did not detect all testfiles correctly!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_MULTI"; then
	scan_failed quikdscan-multiscan.log "quikd did not detect all testfiles correctly in multiscan mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_FDPASS"; then
	scan_failed quikdscan-fdpass.log "quikd did not detect all testfiles correctly in fdpass mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_MULTI_FDPASS"; then
	scan_failed quikdscan-multiscan-fdpass.log "quikd did not detect all testfiles correctly in fdpass+multiscan mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_STREAM"; then
	scan_failed quikdscan-stream.log "quikd did not detect all testfiles correctly in stream mode!"
    fi
    if test "$NFILES" -ne "0$NINFECTED_MULTI_STREAM"; then
	scan_failed quikdscan-multiscan-stream.log "quikd did not detect all testfiles correctly in multiscan+stream mode!"
    fi
    # Test HeuristicScanPrecedence off feature
    run_quikdscan ../quik-phish-exe
    grep "QuikAV-Test-File" quikdscan.log >/dev/null 2>/dev/null;
    if test $? -ne 0; then
	cat quikdscan.log
	die "HeuristicScanPrecedence off test failed!"
    fi
    test_end $1
}

test_quikd2() {
    test_start $1
    start_quikd
    # Run quikd test suite
    test_run_check $CHECK_QUIKD
    val=$?

    # Test RELOAD command
    run_reload_test

    test_end $1
    exit $?
}

test_quikd3() {
    test_start $1
    echo "VirusEvent $abs_srcdir/virusaction-test.sh `pwd` \"Virus found: %v\"" >>test-quikd.conf
    echo "HeuristicScanPrecedence yes" >>test-quikd.conf
    start_quikd
    # Test HeuristicScanPrecedence feature
    run_quikdscan ../quik-phish-exe
    grep "Heuristics.Phishing.Email.SpoofedDomain" quikdscan.log >/dev/null 2>/dev/null ||
        { cat quikdscan.log; die "HeuristicScanPrecedence on test failed!"; }

    if grep "^#define HAVE_FD_PASSING 1" $TOP/quikav-config.h >/dev/null; then
	run_quikdscan_fdpass $TOP/test/quik.exe
	grep "QuikAV-Test-File" quikdscan.log >/dev/null 2>/dev/null ||
	{ cat quikdscan.log; die "FDpassing test failed!";}
    else
	echo "*** No file descriptor passing support, skipping test"
    fi

    rm test-quikd.log
    # Test VirusEvent feature
    run_quikdscan_fileonly $TOP/test/quik.exe
    test -f test-quikd.log || sleep 1
    grep "Virus found: QuikAV-Test-File.UNOFFICIAL" test-quikd.log >/dev/null 2>/dev/null ||
	{ cat test-quikd.log || true; die "Virusaction test failed"; }

    test_end $1
}
