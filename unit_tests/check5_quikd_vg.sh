#!/bin/sh
. $srcdir/check_common.sh
init_valgrind
WRAPPER="$VALGRIND $VALGRIND_FLAGS" test_quikd1 5
end_valgrind 5
