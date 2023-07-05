#!/bin/sh -e

# This script executes the matrix loops, exclude tests and cleaning.
# The matrix can be configured with the following environment variables: MATRIX_CC,
# MATRIX_CMAKE and MATRIX_REMOTE.
: "${MATRIX_CC:=gcc clang}"
: "${MATRIX_CMAKE:=no yes}"
: "${MATRIX_REMOTE:=no yes}"
# Set this variable to "yes" before calling this script to disregard all
# warnings in a particular environment (CI or a local working copy).  Set it
# to "yes" in this script or in build.sh when a matrix subset is known to be
# not warning-free because of the OS, the compiler or whatever other factor
# that the scripts can detect both in and out of CI.
: "${LIBPCAP_TAINTED:=no}"
# Some OSes have native make without parallel jobs support and sometimes have
# GNU Make available as "gmake".
: "${MAKE_BIN:=make}"
# It calls the build.sh script which runs one build with setup environment
# variables: CC, CMAKE and REMOTE.

. ./build_common.sh
print_sysinfo
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=`mktempdir libpcap_build_matrix`
    echo "PREFIX set to '$PREFIX'"
    export PREFIX
fi
COUNT=0
export LIBPCAP_TAINTED
if command -v valgrind >/dev/null 2>&1; then
    VALGRIND_CMD="valgrind --leak-check=full --error-exitcode=1"
    export VALGRIND_CMD
fi

touch .devel configure
for CC in $MATRIX_CC; do
    export CC
    discard_cc_cache
    if gcc_is_clang_in_disguise; then
        echo '(skipped)'
        continue
    fi
    for CMAKE in $MATRIX_CMAKE; do
        export CMAKE
        for REMOTE in $MATRIX_REMOTE; do
            export REMOTE
            COUNT=`increment $COUNT`
            echo_magenta "===== SETUP $COUNT: CC=$CC CMAKE=$CMAKE REMOTE=$REMOTE =====" >&2
            # Run one build with setup environment variables: CC, CMAKE and REMOTE
            run_after_echo ./build.sh
            echo 'Cleaning...'
            if [ "$CMAKE" = yes ]; then rm -rf build; else "$MAKE_BIN" distclean; fi
            purge_directory "$PREFIX"
            run_after_echo git status -suall
            # Cancel changes in configure
            run_after_echo git checkout configure
        done
    done
done
run_after_echo rm -rf "$PREFIX"
echo_magenta "Tested setup count: $COUNT" >&2
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
