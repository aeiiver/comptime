#!/bin/sh

set -ue

{ make -s comptime
  ./comptime --expand -- test/test.c >test/test_expanded_received.c
  diff -u test/test_expanded_received.c test/test_expanded_expected.c
} 2>/dev/null

echo "TEST OK"
