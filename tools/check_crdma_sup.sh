#! /bin/bash

# This script is mostly designed to work with 'dkms' to tell if the CRDMA
# module is expected to be built. It can be used standalone as well, with the
# assumptions that the input arguments are correct. Only very minimal input
# validation is done, as it is expected that dkms would be passing in valid
# 'kernel_ver' and 'srctree' variables.
#
# Example use:
# ./check_crdma_sup.sh 5.14.0-427.22.1.el9_4.x86_64 \
#    /lib/modules/5.14.0-427.22.1.el9_4.x86_64/build

# Only output if the CRDMA_DEBUG environment variable is set
dbg_print () {
    local msg=$1
    if [ -n "${CRDMA_DEBUG}" ]; then
        echo "${msg}"
    fi
}

# "kernel_ver" and "srctree" are expected to be "$kernelver" and
# "$kernel_source_dir" variables from dkms
kernel_ver=$1
srctree=$2

if [ -z "${kernel_ver}" ]; then
    echo "Please provide kernel_ver as first argument"
    exit 1
fi

if [ -z "${srctree}" ]; then
    echo "Please provide path to kernel source as second argument"
    exit 1
fi

utsrelease_h_path="${srctree}/include/generated/utsrelease.h"

BUILD_CRDMA=0
VERSION=$(echo ${kernel_ver} | cut -d '.' -f 1)
PATCHLEVEL=$(echo ${kernel_ver} | cut -d '.' -f 2)

# These are copied and slightly adjusted to work in bash from
# 'nfp-drv-kmods/src/Kbuild'
RHEL_MAJOR=$(awk '/RHEL_MAJOR/ {print $3; found=1} \
		     END {if (found != 1) print 0}' \
		${srctree}/include/generated/uapi/linux/version.h 2>/dev/null || echo 0)
RHEL_MINOR=$(awk '/RHEL_MINOR/ {print $3; found=1} \
		     END {if (found != 1) print 0}' \
		${srctree}/include/generated/uapi/linux/version.h 2>/dev/null || echo 0)
RHEL_RELEASE=$(awk '/RHEL_RELEASE / {print $3; found=1} \
		     END {if (found != 1) print 0}' \
		${srctree}/include/generated/uapi/linux/version.h 2>/dev/null || echo 0)
KYLIN_MAJOR=$(awk '/KYLIN_MAJOR/ {print $3; found=1} \
		     END {if (found != 1) print 0}' \
		${srctree}/include/generated/uapi/linux/version.h 2>/dev/null || echo 0)
KYLIN_MINOR=$(awk '/KYLIN_MINOR/ {print $3; found=1} \
		     END {if (found != 1) print 0}' \
		${srctree}/include/generated/uapi/linux/version.h 2>/dev/null || echo 0)
UTS_UBUNTU_RELEASE_ABI=$(awk '/UTS_UBUNTU_RELEASE_ABI/ {print $3; found=1} \
		     END {if (found != 1) print 0}' \
		${srctree}/include/generated/utsrelease.h 2>/dev/null || echo 0)

dbg_print "Parsed VERSION_MAJOR=${VERSION}"
dbg_print "Parsed PATCHLEVEL=${PATCHLEVEL}"
dbg_print "kernel_ver=${kernel_ver}"
dbg_print "srctree=${srctree}"
dbg_print "RHEL_VERSION=${RHEL_MAJOR}.${RHEL_MINOR}.${RHEL_RELEASE}"
dbg_print "KYLIN_VERSION=${KYLIN_MAJOR}.${KYLIN_MINOR}"
dbg_print "UTS_UBUNTU_RELEASE_ABI=${UTS_UBUNTU_RELEASE_ABI}"

# These functions below are also copied from 'nfp-drv-kmods/src/Kbuild', and
# slightly adjusted to work in bash

# Check if the kernel version is not earlier than given version
#
# @param $1: major version
# @param $2: minor version
kern_ge () {
    [ ${VERSION} -gt $1 -o \
    \( ${VERSION} -eq $1 -a ${PATCHLEVEL} -ge $2 \) ] && echo y
}

# Check if the rhel version is not earlier than given rhel version
#
# @param $1: major version
# @param $2: minor version
rhel_ge () {
    [ ${RHEL_MAJOR} -gt $1 -o \
    \( ${RHEL_MAJOR} -eq $1 -a ${RHEL_MINOR} -ge $2 \) ] && echo y
}

# Check if the kylin version is not earlier than given kylin version
#
# @param $1: major version
# @param $2: minor version
kylin_ge () {
    [ ${KYLIN_MAJOR} -gt $1 -o \
    \( ${KYLIN_MAJOR} -eq $1 -a ${KYLIN_MINOR} -ge $2 \) ] && echo y
}

# Define a variable to indicate whether given file contains given string
#
# @param $1: file to search in
# @param $2: string to match
add_compat_var () {
    grep -q $2 $1 2>/dev/null && echo y
}

# Below are the specific checks for CRDMA. A temporary variable is used instead
# of checking directly, otherwise the 'y' will end up on stdout, which can
# cause problems where this script is used. This also needs to be updated when
# 'nfp-drv-kmods/src/Kbuild' adds/removes checks for CRDMA.

# Linux kernel > = 4.19
tmp=$(kern_ge 4 19)
if [ "${tmp}" = "y" ]; then
	BUILD_CRDMA=y
fi

# Linux kernel  <= 5.16
tmp=$(kern_ge 5 16)
if [ "${tmp}" = "y" ]; then
	BUILD_CRDMA=0
fi

# Support Anolis Linux 8.*
tmp=$(add_compat_var ${utsrelease_h_path} an8)
if [ "${tmp}" = "y" ]; then
	BUILD_CRDMA=y
fi

# CentOS >= 7.6
tmp=$(rhel_ge 7 6)
if [ "${tmp}" = "y" ]; then
	BUILD_CRDMA=y
fi

# Kylin os >= V10SP3
tmp=$(kylin_ge 10 3)
if [ "${tmp}" = "y" ]; then
	BUILD_CRDMA=y
fi

# Do not support Anolis Linux 7.*
# Must be put after rhel_ge judement, Anolis use RHEL_MAJOR and RHEL_MINOR
# too. So we need to set 0 here.
tmp=$(add_compat_var ${utsrelease_h_path} an7)
if [ "${tmp}" = "y" ]; then
	BUILD_CRDMA=0
fi

# Do not support SUSE
if [ -f ${srctree}/include/generated/uapi/linux/suse_version.h ]; then
	BUILD_CRDMA=0
fi

# Do not support UBUNTU
if [ "${UTS_UBUNTU_RELEASE_ABI}" != 0 ]; then
	BUILD_CRDMA=0
fi

dbg_print "BUILD_CRDMA=${BUILD_CRDMA}"

# "return" the final value for BUILD_CRDMA
echo ${BUILD_CRDMA}
