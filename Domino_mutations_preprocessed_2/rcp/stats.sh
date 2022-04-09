#!/bin/bash
DOMINO=/home/ruijief/CaT-Preprocessor/
for p in `ls | grep "\.c"`; do
	time $DOMINO/domino $p > /dev/null
done
