#!/bin/sh -e

# This script runs one build with setup environment variables: CC, CMAKE and
# REMOTE.
: "${CC:=gcc}"
: "${CMAKE:=no}"
: "${REMOTE:=no}"
: "${LIBPCAP_TAINTED:=no}"
: "${MAKE_BIN:=make}"

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
gcc-*/Linux-*)
    # This warning is a bit odd.  It is steadily present in Cirrus CI, but not
    # in Buildbot.  On my Linux system with the same exact distribution and GCC
    # as Cirrus CI it reproduces only if GCC receives the "-g" flag:
    # make CFLAGS=-g -- does not reproduce
    # CFLAGS=-g make -- reproduces
    # make -- reproduces
    #
    # pcap-linux.c:947:8: warning: ignoring return value of 'write', declared
    # with attribute warn_unused_result [-Wunused-result]
    #
    # And even this way it does not make GCC exit with an error when it has
    # reported the warning and has received the "-Werror" flag. So let's keep
    # this block no-op for now.
    ;;
clang-*/NetBSD-*)
    # pcap-bpf.c:1044:18: warning: implicit conversion loses integer precision:
    # 'uint64_t' (aka 'unsigned long') to 'u_int' (aka 'unsigned int')
    # [-Wshorten-64-to-32]
    # pcap-bpf.c:1045:18: warning: implicit conversion loses integer precision:
    # 'uint64_t' (aka 'unsigned long') to 'u_int' (aka 'unsigned int')
    # [-Wshorten-64-to-32]
    # pcap-bpf.c:1274:39: warning: implicit conversion loses integer precision:
    # 'long' to 'suseconds_t' (aka 'int') [-Wshorten-64-to-32]
    LIBPCAP_TAINTED=yes
    ;;
clang-15.*/*)
    # grammar.c:1369:14: warning: variable 'pcap_nerrs' set but not used
    #   [-Wunused-but-set-variable]
    LIBPCAP_TAINTED=yes
    ;;
clang-*/SunOS-5.11)
    # (Solaris 11 and OpenIndiana)
    # pcap-bpf.c:1044:18: warning: implicit conversion loses integer precision:
    #   'uint64_t' (aka 'unsigned long') to 'u_int' (aka 'unsigned int')
    #   [-Wshorten-64-to-32]
    # pcap-bpf.c:1045:18: warning: implicit conversion loses integer precision:
    #   'uint64_t' (aka 'unsigned long') to 'u_int' (aka 'unsigned int')
    #   [-Wshorten-64-to-32]
    # fad-getad.c:266:52: warning: implicit conversion loses integer precision:
    #   'uint64_t'(aka 'unsigned long') to 'bpf_u_int32' (aka 'unsigned int')
    #   [-Wshorten-64-to-32]
    # (Solaris 11)
    # pcap-bpf.c:1843:22: warning: implicit conversion loses integer precision:
    #   'long' to 'int' [-Wshorten-64-to-32]
    # (OpenIndiana)
    # rpcapd.c:393:18: warning: this function declaration is not a prototype
    #   [-Wstrict-prototypes]
    [ "`uname -p`" = i386 ] && LIBPCAP_TAINTED=yes
    ;;
suncc-5.1[45]/SunOS-5.11)
    # "scanner.l", line 257: warning: statement not reached
    # (186 warnings for scanner.l)
    #
    # "./filtertest.c", line 259: warning: statement not reached
    # "./filtertest.c", line 276: warning: statement not reached
    # "./filtertest.c", line 281: warning: statement not reached
    LIBPCAP_TAINTED=yes
    ;;
*/Haiku-*)
    # (GCC 8.3.0 and later, Clang 9.0.1.)
    # pcap-haiku.cpp:55:21: warning: unused variable 'handlep' [-Wunused-variable]
    # pcap-haiku.cpp:50:37: warning: unused parameter 'maxPackets' [-Wunused-parameter]
    # pcap-haiku.cpp:111:47: warning: unused parameter 'buffer' [-Wunused-parameter]
    # pcap-haiku.cpp:111:59: warning: unused parameter 'size' [-Wunused-parameter]
    # pcap-haiku.cpp:268:26: warning: unused parameter 'name' [-Wunused-parameter]
    # pcap-haiku.cpp:274:26: warning: unused parameter 'name' [-Wunused-parameter]
    # pcap-haiku.cpp:274:58: warning: unused parameter 'errbuf' [-Wunused-parameter]
    #
    # (The warnings below come from GCC and Clang in CMake builds after installing
    # all system updates.)
    # gencode.c:4143:9: warning: converting a packed 'struct in6_addr' pointer
    #   (alignment 1) to a 'uint32_t' {aka 'unsigned int'} pointer (alignment 4) may
    #   result in an unaligned pointer value [-Waddress-of-packed-member]
    # gencode.c:4144:9: warning: converting a packed 'struct in6_addr' pointer
    #   (alignment 1) to a 'uint32_t' {aka 'unsigned int'} pointer (alignment 4) may
    #   result in an unaligned pointer value [-Waddress-of-packed-member]
    # gencode.c:7189:9: warning: converting a packed 'struct in6_addr' pointer
    #   (alignment 1) to a 'uint32_t' {aka 'unsigned int'} pointer (alignment 4) may
    #   result in an unaligned pointer value [-Waddress-of-packed-member]
    # gencode.c:7190:9: warning: converting a packed 'struct in6_addr' pointer
    #   (alignment 1) to a 'uint32_t' {aka 'unsigned int'} pointer (alignment 4) may
    #   result in an unaligned pointer value [-Waddress-of-packed-member]
    LIBPCAP_TAINTED=yes
    ;;
esac
[ "$LIBPCAP_TAINTED" != yes ] && CFLAGS=`cc_werr_cflags`

if [ "$CMAKE" = no ]; then
    run_after_echo ./configure --prefix="$PREFIX" --enable-remote="$REMOTE"
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
    run_after_echo cmake ${CFLAGS:+-DEXTRA_CFLAGS="$CFLAGS"} \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DENABLE_REMOTE="$REMOTE" ..
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
# VALGRIND_CMD is meant either to collapse or to expand.
# shellcheck disable=SC2086
if [ "$CMAKE" = no ]; then
    run_after_echo $VALGRIND_CMD testprogs/findalldevstest
    run_after_echo "$MAKE_BIN" releasetar
else
    run_after_echo $VALGRIND_CMD run/findalldevstest
fi
handle_matrix_debug
if [ "$DELETE_PREFIX" = yes ]; then
    run_after_echo rm -rf "$PREFIX"
fi
# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
