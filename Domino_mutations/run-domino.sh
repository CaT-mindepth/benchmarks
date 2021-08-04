#!/bin/bash
set -x
rm -rf *.domino
for x in `ls $1 | grep .c` ; do 
  $DOMINO/domino $1/$x | clang-format > $1/$x.domino
done

