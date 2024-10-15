#! /bin/bash

potential_pciid_files=\
'/usr/share/pci.ids '\
'/usr/share/hwdata/pci.ids '\
'/usr/share/misc/pci.ids '\
'/var/lib/pciutils/pci.ids '


usage () {
    cat <<EOH

Usage: corigine_pciids[.sh] apply|revert

Copyright (C) 2024 Corigine, Inc

This script updates the system "pci.ids" file(s).
The following files will be affected if they exist:
$potential_pciid_files

a|apply         Insert Corigine vendor/device IDs into all files.
r|revert        Revert all changes made by this script.

EOH
    exit 1
}


# This function simply overwrites the file `target_file`. The contents of the
# file will be largely unchanged, but with Corigine PCI ID entries inserted
# appropriately. This is usually a simple operation, but this function
# is quite complicated for 2 reasons:
# 1. Flexibility for any combination of update lines being missing.
# 2. Wide support for any OS/distribution. We cannot rely on tools like
#    Python, Perl, or even awk being available. This function only requires
#    bash-2.05b (released 17/07/2002). If sed and grep are available, it runs
#    significantly faster though.
apply () {
        local target_file="$1"
        local target_file_bak="${target_file}.corigine_backup"
        local target_file_tmp="/tmp/$(basename "${target_file}").tmp"

        if [[ ! -f "$target_file" ]]; then
                return 0  # Nothing to apply because file does not exist.
        fi

        # Note: It would have been convenient to combine the IDs into 64 bit
        #       hex numbers, but `bash` (or `test`?) interprets hex as signed
        #       numbers. So we need to be careful of the system's integer size.
        #       Keep everything as 16 bits.
        set_pciids_id () {
                pciids_just_echo_line=false
                if [[ "$pciids_line" =~ $VENDOR_REGEX ]]; then
                        pciids_vendor_id="${pciids_line:0:4}"
                        pciids_device_id=0000
                        pciids_subdev_id1=0000
                        pciids_subdev_id2=0000
                elif [[ "$pciids_line" =~ $DEVICE_REGEX ]]; then
                        pciids_device_id="${pciids_line:1:4}"
                        pciids_subdev_id1=0000
                        pciids_subdev_id2=0000
                elif [[ "$pciids_line" =~ $SUBDEV_REGEX ]]; then
                        pciids_subdev_id1="${update_line:2:4}"
                        pciids_subdev_id2="${update_line:7:4}"
                else
                        pciids_just_echo_line=true
                fi
        }

        # See comment above.
        compare_update_and_pciid () {
                if [[ $pciids_eof == true ]]; then
                        # When the pciids_line is invalid because EOF has been
                        # reached, always prefer the update_line.
                        echo lt; return
                elif [[ $pciids_just_echo_line == true ]]; then
                        # When the pciids_line is unrecognised,
                        # always prefer the pciids_line.
                        echo gt; return
                fi

                if [[ 0x$update_vendor_id -lt 0x$pciids_vendor_id ]]; then
                        echo lt; return
                elif [[ 0x$update_vendor_id -gt 0x$pciids_vendor_id ]]; then
                        echo gt; return
                fi

                if [[ 0x$update_device_id -lt 0x$pciids_device_id ]]; then
                        echo lt; return
                elif [[ 0x$update_device_id -gt 0x$pciids_device_id ]]; then
                        echo gt; return
                fi

                if [[ 0x$update_subdev_id1 -lt 0x$pciids_subdev_id1 ]]; then
                        echo lt; return
                elif [[ 0x$update_subdev_id1 -gt 0x$pciids_subdev_id1 ]]; then
                        echo gt; return
                fi

                if [[ 0x$update_subdev_id2 -lt 0x$pciids_subdev_id2 ]]; then
                        echo lt; return
                elif [[ 0x$update_subdev_id2 -gt 0x$pciids_subdev_id2 ]]; then
                        echo gt; return
                fi

                echo eq; return
        }

        VENDOR_REGEX='^[0-9a-fA-F]{4}  .*'
        DEVICE_REGEX='^'$'\t''[0-9a-fA-F]{4}  .*'
        SUBDEV_REGEX='^'$'\t''{2}[0-9a-fA-F]{4} [0-9a-fA-F]{4}  .*'
        COMMENT_MARK="# Next line added by agilio-nfp-driver package"

        if which grep 1>/dev/null 2>&1 && which sed 1>/dev/null 2>&1; then
                can_optimise=true
        else
                can_optimise=false
        fi

        # Preserve whitespace on all reads.
        IFS=

        # Pipe in updates via a here-string (see end of loop).
        while true; do
                # Save input/output file descriptors.
                exec 3>$target_file_tmp
                exec 4<$target_file
                exec 5<&0

                # All output goes to `target_file_tmp`
                exec 1>&3

                # Get first line of `target_file`
                pciids_eof=false
                pciids_just_echo_line=false
                exec 0<&4
                read -r pciids_line || pciids_eof=true

                # Initialise variables
                pciids_vendor_id=0000
                pciids_device_id=0000
                pciids_subdev_id1=0000
                pciids_subdev_id2=0000
                set_pciids_id

                # This loop reads the updates (from the here-string)
                exec 0<&5
                while read -r update_line; do
                        if [[ "$update_line" =~ $VENDOR_REGEX ]]; then
                                update_vendor_id="${update_line:0:4}"
                                update_device_id=0000
                                update_subdev_id1=0000
                                update_subdev_id2=0000
                        elif [[ "$update_line" =~ $DEVICE_REGEX ]]; then
                                update_device_id="${update_line:1:4}"
                                update_subdev_id1=0000
                                update_subdev_id2=0000
                        elif [[ "$update_line" =~ $SUBDEV_REGEX ]]; then
                                update_subdev_id1="${update_line:2:4}"
                                update_subdev_id2="${update_line:7:4}"
                        else
                                # Ignore all unrecognised update lines
                                # (typically comments)
                                continue
                        fi

                        # All inner reads come from `target_file`
                        exec 0<&4

                        # Optimisation: Quick read to the position.
                        # This block may be removed without changing the outcome.
                        if [[ $can_optimise == true ]]; then
                                if grep -q "$update_line" $target_file; then
                                        echo "$pciids_line"
                                        sed "/$update_line/q"
                                        pciids_vendor_id=$update_vendor_id
                                        pciids_device_id=$update_device_id
                                        pciids_subdev_id1=$update_subdev_id1
                                        pciids_subdev_id2=$update_subdev_id2
                                        read -r pciids_line || pciids_eof=true
                                        set_pciids_id
                                        exec 0<&5
                                        continue
                                fi
                        fi

                        comparison=$(compare_update_and_pciid)
                        while [[ $comparison == gt ]]; do
                                echo "$pciids_line"
                                read -r pciids_line || pciids_eof=true
                                set_pciids_id
                                comparison=$(compare_update_and_pciid)
                        done

                        # Do not overwrite if the source and the updates contain the same ID
                        if [[ $comparison == eq ]]; then
                                echo "$pciids_line"
                                read -r pciids_line || pciids_eof=true
                                set_pciids_id
                        else
                                echo "$COMMENT_MARK"
                                echo "$update_line"
                        fi

                        # Set input back to `updates_file` for outer loop.
                        exec 0<&5
                done

                if [[ $pciids_eof != true ]]; then
                        # If there's no more update content, just apply the rest of the source
                        echo "$pciids_line"
                        exec 0<&4
                        read -r pciids_line || pciids_eof=true
                        while [[ $pciids_eof != true ]]; do
                                echo "$pciids_line"
                                read -r pciids_line || pciids_eof=true
                        done
                fi

                # Close input/output file descriptors.
                exec 3>&-
                exec 4<&-
                exec 5<&-

                break
        done 1>/dev/null <<< '
# This here-string contains PCI vendor/device IDs/descriptions for Corigine
# cards.

# Contents of this here-string must obey the following rules, otherwise the
# script will fail silently and potentially leave a broken `pci.ids` file:
# - IDs must be in ascending order.
# - Indentation in this here-string must use tabs.
# - Vendor lines must:
#   - Have format "[0-9a-fA-F]{4}  <vendor name>"
# - Device lines must:
#   - Have format "\t[0-9a-fA-F]{4}  <device name>"
#   - Be preceded by a vendor line.
# - Sub-device lines must:
#   - Have format "\t\t[0-9a-fA-F]{4} [0-9a-fA-F]{4}  <sub-device name>"
#   - Be preceded by device lines.
# - Please note the double spaces ("  ") in the formats above.
# - No comments on the same line as a vendor/device/sub-device entry.

# NOTE: Only IDs that do not exist will be inserted. If an ID exists but has a
#       different name/description, it will NOT be updated.

1da8  Corigine, Inc.
	3800  Network Flow Processor 3800
	3803  Network Flow Processor 3800 Virtual Function
	4000  Network Flow Processor 4000
	6003  Network Flow Processor 6003 Virtual Function
'

        # Create backup.
        target_file_bak="${target_file}.corigine_backup"
        if ! \cp -f "$target_file" "$target_file_bak"; then
                echo "Failed to create backup of '${target_file}'" 1>&2
                echo "Aborting pci.ids update for this file." 1>&2
                return 1
        fi

        # Overwrite `target_file` with new version.
        \mv -f "$target_file_tmp" "$target_file"
}


# This function simply overwrites the file `target_file`. The contents of the
# file will be largely unchanged, but with all "# Next line added by
# agilio-nfp-driver package" comments and the line immediately following them
# removed.
revert () {
        local target_file="$1"
        local target_file_tmp="/tmp/$(basename "${target_file}").tmp"

        if [ ! -f "$target_file" ]; then
                return 0  # Nothing to revert because file does not exist.
        fi

        # Set up input/output file descriptors.
        exec 3>$target_file_tmp
        exec 4<$target_file

        COMMENT_MARK="# Next line added by agilio-nfp-driver package"

        # Create sub-shell without standard file descriptors.
        while true; do
                # All output goes to `target_file_tmp`
                exec 1>&3
                # All input comes from `target_file`
                exec 0<&4
                while IFS= read -r pciids_line; do
                        if [[ "$pciids_line" == "$COMMENT_MARK" ]]; then
                                # Read twice to skip over the comment and the next line.
                                read -r pciids_line
                        else
                                echo "$pciids_line"
                        fi
                done

                break
        done 0</dev/null 1>/dev/null

        # Close input/output file descriptors.
        exec 3>&-
        exec 4<&-

        # Overwrite `target_file` with new version.
        \mv -f "$target_file_tmp" "$target_file"
}


if [[ "$1" == "apply" || "$1" == "a" ]]; then
        for pciids in $potential_pciid_files; do
                ( set -e; apply $pciids )
        done
elif [[ "$1" == "revert" || "$1" == "r" ]]; then
        for pciids in $potential_pciid_files; do
                ( set -e; revert $pciids )
        done
else
        usage
fi
