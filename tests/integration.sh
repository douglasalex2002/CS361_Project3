#!/bin/bash

EXE="../dhcps"

function run_test {

    # parameters
    TAG=$1
    shift
    ARGS=$1
    shift

    PTAG=$(printf '%-30s' "$TAG")
    if [[ $(echo $TAG | cut -d'_' -f1) == $SKIP_C || 
          $(echo $TAG | cut -d'_' -f1) == $SKIP_B ||
          $(echo $TAG | cut -d'_' -f1) == $SKIP_A ]] ; then
        echo "$PTAG SKIPPED (previous phases not complete)"
        return
    fi

    # file paths
    OUTPUT=outputs/$TAG.txt
    DIFF=outputs/$TAG.diff
    EXPECT=expected/$TAG.txt
    VALGRND=valgrind/$TAG.txt

    SARGS="-s 1"
    # run test and compare output to the expected version
    if [[ $TAG == "A_threads" ]] ; then
        SARGS="-t ${SARGS}0"
    fi
		if [[ $(echo $TAG | cut -d'_' -f1) == 'D' ]] ; then
			  $EXE $SARGS >"$OUTPUT" 2>/dev/null &
		else
        $EXE $SARGS >/dev/null 2>&1 &
		fi
    sleep .5 
    if [[ $TAG == "A_threads" ]] ; then
        ./threads 2>/dev/null >"$OUTPUT"
		elif [[ $(echo $TAG | cut -d'_' -f1) == 'D' ]] ; then
        ./client $ARGS >/dev/null 2>&1
		else
        ./client $ARGS 2>/dev/null >"$OUTPUT"
    fi
  	sleep 1.5

    diff -u "$OUTPUT" "$EXPECT" >"$DIFF"
    if [ -s "$DIFF" ]; then

        if [[ $TAG == "A_threads" ]] ; then
            echo "$PTAG FAIL - Command line: $EXE $SARGS ; ./threads $ARGS"
        else
            echo "$PTAG FAIL - Command line: $EXE $SARGS ; ./client $ARGS"
        fi
        if [[ $(echo $PTAG | cut -d'_' -f1) == 'D' ]] ; then
            SKIP_C="C"
            SKIP_B="B"
            SKIP_A="A"
        elif [[ $(echo $PTAG | cut -d'_' -f1) == 'C' ]] ; then
            SKIP_B="B"
            SKIP_A="A"
        elif [[ $(echo $PTAG | cut -d'_' -f1) == 'B' ]] ; then
            SKIP_A="A"
        fi
    else
        echo "$PTAG pass"
    fi

    # run valgrind
    #valgrind $EXE -s 2 >"$VALGRND" 2>&1 &
    #sleep 1
    #./client $ARGS >/dev/null 2>&1
  	#sleep 2
}

# initialize output folders
mkdir -p outputs
mkdir -p valgrind
rm -f outputs/* valgrind/*

# run individual tests
source itests.include

# check for memory leaks
#LEAK=`cat valgrind/*.txt | grep 'definitely lost' | grep -v ' 0 bytes in 0 blocks'`
#LEAK=
#if [ -z "$LEAK" ]; then
#    echo "No memory leak found."
#else
#    echo "Memory leak(s) found. See files listed below for details."
#    grep 'definitely lost' valgrind/*.txt | sed -e 's/:.*$//g' | sed -e 's/^/  - /g'
#fi

