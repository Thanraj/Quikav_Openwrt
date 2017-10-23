#!/bin/sh
if test ! `basename $QUIK_VIRUSEVENT_FILENAME` = "quik.exe"; then
	echo "VirusEvent incorrect: $QUIK_VIRUSEVENT_FILENAME" >$1/test-quikd.log
	exit 1
fi
if test ! "x$QUIK_VIRUSEVENT_VIRUSNAME" = "xQuikAV-Test-File.UNOFFICIAL"; then
	echo "VirusName incorrect: $QUIK_VIRUSEVENT_VIRUSNAME" >$1/test-quikd.log
	exit 2
fi
echo $2 >$1/test-quikd.log
