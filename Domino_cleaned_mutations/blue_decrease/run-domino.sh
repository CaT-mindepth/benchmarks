#!/bin/bash
set -x
rm -rf *.domino
for x in `ls | grep .c` ; do 
  $DOMINO/domino $x | clang-format > $x.domino
done

