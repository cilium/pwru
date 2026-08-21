#!/bin/sh -e

# This script runs one build with setup environment variables: CC, CMAKE, IPV6
# and REMOTE.
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${IPV6:=no}"
: "${REMOTE:=no}"
: "${LIBPCAP_TAINTED:=no}"
: "${LIBPCAP_CMAKE_TAINTED:=no}"
: "${MAKE_BIN:=make}"
# At least one OS (AIX 7) where this software can build does not have at least
# one command (mktemp) required for a successful run of "make releasetar".
: "${TEST_RELEASETAR:=yes}"

. ./build_common.sh
# Install directory prefix
if [ -z "$PREFIX" ]; then
    PREFIX=`mktempdir libpcap_build`
    echo "PREFIX set to '$PREFIX'"
    DELETE_PREFIX=yes
fi

print_cc_version

# The norm is to compile without any warnings, but libpcap builds on some OSes
# are not warning-free for one or another reason.  If you manage to fix one of
# these cases, please remember to remove respective exemption below to help any
# later warnings in the same matrix subset trigger an error.
# shellcheck disable=SC2221,SC2222
case `cc_id`/`os_id` in
tcc-*/*)
    # At least one warning is expected because TCC does not implement
    # thread-local storage.
    LIBPCAP_TAINTED=yes
    ;;
*)
    ;;
esac
[ "$LIBPCAP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

case `cc_id`/`os_id` in
clang-*/SunOS-5.11)
    # Work around https://www.illumos.org/issues/16369
    [ "`uname -o`" = illumos ] && grep -Fq OpenIndiana /etc/release && CFLAGS="-Wno-fuse-ld-path${CFLAGS:+ $CFLAGS}"
    ;;
esac

# If necessary, set LIBPCAP_CMAKE_TAINTED here to exempt particular cmake from
# warnings. Use as specific terms as possible (e.g. some specific version and
# some specific OS).

[ "$LIBPCAP_CMAKE_TAINTED" != yes ] && CMAKE_OPTIONS='-Werror=dev'

if [ "$CMAKE" = no ]; then
    run_after_echo ./autogen.sh
    run_after_echo ./configure --prefix="$PREFIX" --enable-ipv6="$IPV6" --enable-remote="$REMOTE"
else
    # Remove the leftovers from any earlier in-source builds, so this
    # out-of-source build does not break because of that.
    # https://gitlab.kitware.com/cmake/community/-/wikis/FAQ#what-is-an-out-of-source-build
    # (The contents of build/ remaining after an earlier unsuccessful attempt
    # can fail subsequent build attempts too, sometimes in non-obvious ways,
    # so remove that directory as well.)
    run_after_echo rm -rf CMakeFiles/ CMakeCache.txt build/
    run_after_echo mkdir build
    run_after_echo cd build
    run_after_echo cmake --version
    run_after_echo cmake ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
        ${CMAKE_OPTIONS:+"$CMAKE_OPTIONS"} \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DINET6="$IPV6" -DENABLE_REMOTE="$REMOTE" ..
fi
run_after_echo "$MAKE_BIN" -s clean
if [ "$CMAKE" = no ]; then
    run_after_echo "$MAKE_BIN" -s ${CFLAGS:+CFLAGS="$CFLAGS"}
    run_after_echo "$MAKE_BIN" -s testprogs ${CFLAGS:+CFLAGS="$CFLAGS"}
else
    # The "-s" flag is a no-op and CFLAGS is set using -DEXTRA_CFLAGS above.
    run_after_echo "$MAKE_BIN"
    run_after_echo "$MAKE_BIN" testprogs
fi
run_after_echo "$MAKE_BIN" install

run_after_echo "$PREFIX/bin/pcap-config" --help
run_after_echo "$PREFIX/bin/pcap-config" --version
run_after_echo "$PREFIX/bin/pcap-config" --cflags
run_after_echo "$PREFIX/bin/pcap-config" --libs
run_after_echo "$PREFIX/bin/pcap-config" --additional-libs
run_after_echo "$PREFIX/bin/pcap-config" --libs --static
run_after_echo "$PREFIX/bin/pcap-config" --additional-libs --static
run_after_echo "$PREFIX/bin/pcap-config" --libs --static-pcap-only
run_after_echo "$PREFIX/bin/pcap-config" --additional-libs --static-pcap-only

# VALGRIND_CMD is meant either to collapse or to expand.
# shellcheck disable=SC2086
if [ "$CMAKE" = no ]; then
    run_after_echo $VALGRIND_CMD testprogs/versiontest
    run_after_echo $VALGRIND_CMD testprogs/findalldevstest
    [ "$TEST_RELEASETAR" = yes ] && run_after_echo "$MAKE_BIN" releasetar
else
    run_after_echo $VALGRIND_CMD run/versiontest
    run_after_echo $VALGRIND_CMD run/findalldevstest
fi
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
