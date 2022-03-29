#!/bin/bash
set -x
rm -rf *.domino
for x in `ls $1 | grep .c` ; do 
  time  $DOMINO/domino $1/$x > $x.in
done

