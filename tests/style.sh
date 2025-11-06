#!/bin/bash

STYLE="gnu"

IGNORE=()
FAIL=0

function comp_file {

    SRC=$1
    SRC_NAME=$2

    # file paths
    FORMAT=ckstyle/${SRC_NAME}.$STYLE
    DIFF=ckstyle/${SRC_NAME}.diff

    # run clang-format and compare results
    clang-format --style=$STYLE $source > $FORMAT
    diff -u $SRC $FORMAT >$DIFF

    PTAG=$(printf '%-30s' "$SRC_NAME")
    if [ -s $DIFF ]; then
        echo "$PTAG FAIL (see $DIFF for details)"
        FAIL=1
    else
        echo "$PTAG pass"
				rm $DIFF
    fi
    rm $FORMAT
}

mkdir -p ckstyle
rm -f ckstyle/*

for source in $(ls ../*.c ../*.h) ; do
    SKIP=0
    src=$(basename $source)
    for ignore in ${IGNORE[*]} ; do
        if [ "$src" = "$ignore" ] ; then
            SKIP=1
        fi
    done
    if [ $SKIP = 0 ] ; then
        comp_file $source $src
    fi
done

if [ $FAIL != 0 ] ; then
    echo "Code that does not adhere to GNU standards will not be accepted."
		echo "You must fix these files before submission."
else
    echo "Code correctly adheres to required style."
fi
