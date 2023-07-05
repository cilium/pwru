#!/bin/sh -e

# The only purpose of the above shebang is to orient shellcheck right.
# To make CI scripts maintenance simpler, copies of this file in the
# libpcap, tcpdump and tcpslice git repositories should be identical.
# Please mind that Solaris /bin/sh before 11 does not support the $()
# command substitution syntax, hence the "-e SC2006" flag in Makefile.

# A poor man's mktemp(1) for OSes that don't have one (e.g. AIX 7, Solaris 9).
mktempdir_diy() {
    while true; do
        # /bin/sh implements $RANDOM in AIX 7, but not in Solaris before 11,
        # thus use dd and od instead.
        mktempdir_diy_suffix=`dd if=/dev/urandom bs=4 count=1 2>/dev/null | od -t x -A n | head -1 | tr -d '\t '`
        [ -z "$mktempdir_diy_suffix" ] && return 1
        mktempdir_diy_path="${TMPDIR:-/tmp}/${1:?}.${mktempdir_diy_suffix}"
        # "test -e" would be more appropriate, but it is not available in
        # Solaris /bin/sh before 11.
        if [ ! -d "$mktempdir_diy_path" ]; then
            mkdir "$mktempdir_diy_path"
            chmod go= "$mktempdir_diy_path"
            echo "$mktempdir_diy_path"
            break
        fi
        # Try again (very unlikely, just in case).
    done
}

mktempdir() {
    mktempdir_prefix=${1:-tmp}
    case `os_id` in
    Darwin-*|FreeBSD-*|NetBSD-*)
        # In these operating systems mktemp(1) always appends an implicit
        # ".XXXXXXXX" suffix to the requested template when creating a
        # temporary directory.
        mktemp -d -t "$mktempdir_prefix"
        ;;
    SunOS-5.10|SunOS-5.11)
        # Although the suffix is optional, specify it for consistent results.
        mktemp -d -t "${mktempdir_prefix}.XXXXXXXX"
        ;;
    SunOS-*|AIX-*)
        mktempdir_diy "$mktempdir_prefix"
        ;;
    *)
        # At least Haiku, Linux and OpenBSD implementations require explicit
        # trailing X'es in the template, so make it the same suffix as above.
        mktemp -d -t "${mktempdir_prefix}.XXXXXXXX"
        ;;
    esac
}

print_sysinfo() {
    uname -a
    printf 'OS identification: '
    os_id
    date
}

# Try to make the current C compiler print its version information (usually
# multi-line) to stdout.
cc_version_nocache() {
    : "${CC:?}"
    case `basename "$CC"` in
    gcc*|egcc*|clang*)
        # GCC and Clang recognize --version, print to stdout and exit with 0.
        "$CC" --version
        ;;
    xl*)
        # XL C 12.1 and 13.1 recognize "-qversion", print to stdout and exit
        # with 0. XL C 12.1 on an unknown command-line flag displays its man
        # page and waits.
        # XL C 16.1 recognizes "-qversion" and "--version", prints to stdout
        # and exits with 0. Community Edition also prints a banner to stderr.
        "$CC" -qversion 2>/dev/null
        ;;
    sun*)
        # Sun compilers recognize -V, print to stderr and exit with an error.
        "$CC" -V 2>&1 || :
        ;;
    cc)
        case `os_id` in
        SunOS-*)
            # Most likely Sun C.
            "$CC" -V 2>&1 || :
            ;;
        Darwin-*)
            # Most likely Clang.
            "$CC" --version
            ;;
        Linux-*|FreeBSD-*|NetBSD-*|OpenBSD-*)
            # Most likely Clang or GCC.
            "$CC" --version
            ;;
        esac
        ;;
    *)
        "$CC" --version || "$CC" -V || :
        ;;
    esac
}

cc_version() {
    echo "${cc_version_cached:=`cc_version_nocache`}"
}

print_cc_version() {
    cc_version
    printf 'Compiler identification: '
    cc_id
}

# For the current C compiler try to print a short and uniform identification
# string (such as "gcc-9.3.0") that is convenient to use in a case statement.
cc_id_nocache() {
    cc_id_firstline=`cc_version | head -1`
    : "${cc_id_firstline:?}"

    cc_id_guessed=`echo "$cc_id_firstline" | sed 's/^.*clang version \([0-9\.]*\).*$/clang-\1/'`
    if [ "$cc_id_firstline" != "$cc_id_guessed" ]; then
        echo "$cc_id_guessed"
        return
    fi

    cc_id_guessed=`echo "$cc_id_firstline" | sed 's/^IBM XL C.*, V\([0-9\.]*\).*$/xlc-\1/'`
    if [ "$cc_id_firstline" != "$cc_id_guessed" ]; then
        echo "$cc_id_guessed"
        return
    fi

    cc_id_guessed=`echo "$cc_id_firstline" | sed 's/^.* Sun C \([0-9\.]*\) .*$/suncc-\1/'`
    if [ "$cc_id_firstline" != "$cc_id_guessed" ]; then
        echo "$cc_id_guessed"
        return
    fi

    # OpenBSD default GCC:
    # "gcc (GCC) 4.2.1 20070719"
    # RedHat GCC:
    # "gcc (GCC) 8.3.1 20190223 (Red Hat 8.3.1-2)"
    # "gcc (GCC) 10.3.1 20210422 (Red Hat 10.3.1-1)"
    # other GCC packages:
    # "sparc-sun-solaris2.9-gcc (GCC) 4.2.0 (gccfss)"
    # "gcc (GCC) 5.5.0"
    # "gcc (nb4 20200810) 7.5.0"
    # "gcc (OpenIndiana 7.5.0-il-0) 7.5.0"
    # "gcc (Debian 8.3.0-6) 8.3.0"
    # "gcc (Raspbian 8.3.0-6+rpi1) 8.3.0"
    # "egcc (GCC) 8.4.0"
    # "gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0"
    # "gcc (FreeBSD Ports Collection) 10.3.0"
    cc_id_guessed=`echo "$cc_id_firstline" | sed 's/^.* (.*) \([0-9\.]*\).*$/gcc-\1/'`
    if [ "$cc_id_firstline" != "$cc_id_guessed" ]; then
        echo "$cc_id_guessed"
        return
    fi
}

cc_id() {
    echo "${cc_id_cached:=`cc_id_nocache`}"
}

# Call this function each time CC has changed.
discard_cc_cache() {
    cc_version_cached=
    cc_id_cached=
}

# For the current C compiler try to print CFLAGS value that tells to treat
# warnings as errors.
cc_werr_cflags() {
    case `cc_id` in
    gcc-*|clang-*)
        echo '-Werror'
        ;;
    xlc-*)
        # XL C 12.1 and 13.1 recognize "-qhalt=w". XL C 16.1 recognizes that
        # and "-Werror".
        echo '-qhalt=w'
        ;;
    suncc-*)
        echo '-errwarn=%all'
        ;;
    esac
}

# Tell whether "gcc" is a symlink to Clang (this is the case on macOS).
gcc_is_clang_in_disguise() {
    case `cc_id`/`basename "${CC:?}"` in
    clang-*/gcc)
        return 0
        ;;
    esac
    return 1
}

os_id() {
    # OS does not change between builds or in the middle of a build, so it is
    # fine to cache uname output.
    : "${os_id_sysname:=`uname -s`}"
    printf '%s-' "$os_id_sysname"
    : "${os_id_release:=`uname -r`}"
    case "$os_id_sysname" in
    AIX)
        : "${os_id_version:=`uname -v`}"
        echo "${os_id_version}.${os_id_release}"
        ;;
    Darwin|NetBSD|OpenBSD|SunOS)
        echo "$os_id_release"
        ;;
    FreeBSD|Linux)
        # Meaningful version is usually the substring before the first dash.
        echo "$os_id_release" | sed 's/^\([0-9\.]*\).*$/\1/'
        ;;
    Haiku)
        # Meaningful version is the substring before the plus sign.
        # "hrev55181" stands for "R1/beta3".
        # "hrev54154" stands for "R1/beta2".
        : "${os_id_version:=`uname -v`}"
        echo "$os_id_version" | sed 's/^\(hrev.*\)+.*$/\1/'
        ;;
    *)
        echo 'UNKNOWN'
        ;;
    esac
}

increment() {
    # No arithmetic expansion in Solaris /bin/sh before 11.
    echo "${1:?} + 1" | bc
}

# Display text in magenta.
echo_magenta() {
    # ANSI magenta, the imploded text, ANSI reset, newline.
    printf '\033[35;1m%s\033[0m\n' "$*"
}

# Run a command after displaying it.
run_after_echo() {
    : "${1:?}" # Require at least one argument.
    printf '$ %s\n' "$*"
    "$@"
}

print_so_deps() {
    case `os_id` in
    Darwin-*)
        run_after_echo otool -L "${1:?}"
        ;;
    *)
        run_after_echo ldd "${1:?}"
        ;;
    esac
}

# Beware that setting MATRIX_DEBUG for tcpdump or tcpslice will produce A LOT
# of additional output there and in any nested libpcap builds. Multiplied by
# the matrix size, the full output log size might exceed limits of some CI
# systems (as it had previously happened with Travis CI). Use with caution on
# a reduced matrix.
handle_matrix_debug() {
    [ "$MATRIX_DEBUG" != yes ] && return
    echo '$ cat Makefile [...]'
    sed '/^# DO NOT DELETE THIS LINE -- mkdep uses it.$/q' <Makefile
    run_after_echo cat config.h
    [ "$CMAKE" = yes ] || run_after_echo cat config.log
}

purge_directory() {
    if [ "`os_id`" = SunOS-5.11 ]; then
        # In Solaris 11 /bin/sh the pathname expansion of "*" always includes
        # "." and "..", so the straightforward rm would always fail.
        (
            cd "${1:?}"
            for pd_each in *; do
                if [ "$pd_each" != . ] && [ "$pd_each" != .. ]; then
                    rm -rf "$pd_each"
                fi
            done
        )
    else
        rm -rf "${1:?}"/*
    fi
}

# vi: set tabstop=4 softtabstop=0 expandtab shiftwidth=4 smarttab autoindent :
