#!/bin/sh
. $srcdir/check_common.sh
init_valgrind
WRAPPER="$VALGRIND $VALGRIND_FLAGS" test_quikd2 6
end_valgrind 6
