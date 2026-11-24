#!/bin/sh
# Pure helpers for the historical display watchdog. No device writes.
# Source only; caller supplies B (BusyBox path, or empty for host tools).

r800_uint() {
    case "${1:-}" in
        0) return 0 ;;
        ""|*[!0-9]*|0*) return 1 ;;
    esac
    [ "${#1}" -le 12 ]
}

r800_irq_total() {
    # Count all online CPU columns, not only CPU0. Reject missing or
    # ambiguous frame IRQ names rather than interpreting them as a stall.
    $B awk '
        NR == 1 {
            for (i = 1; i <= NF; i++)
                if ($i ~ /^CPU[0-9]+$/) cpus++
            if (!cpus || cpus != NF) bad = 1
            next
        }
        {
            found = 0
            for (i = cpus + 2; i <= NF; i++)
                if ($i ~ /^decon_f[0-9]*$/) found = 1
            if (!found) next
            rows++
            if ($1 !~ /^[0-9]+:$/ || NF < cpus + 2) bad = 1
            for (i = 2; i <= cpus + 1; i++) {
                if ($i !~ /^[0-9]+$/ || length($i) > 12) bad = 1
                else total += $i
            }
        }
        END {
            if (bad || rows != 1 || total > 999999999999) exit 1
            printf "%.0f\n", total
        }
    ' "$1"
}

r800_process_start_ticks() {
    r800_uint "$2" && [ "$2" -gt 0 ] || return 1
    # /proc/PID/stat comm may contain spaces and right parentheses.
    # After the final ") ", starttime (field 22) becomes field 20.
    $B awk -v pid="$2" '
        NR == 1 {
            if ($1 != pid || $0 !~ /\) /) exit 1
            sub(/^.*\) /, "")
            if (NF < 20 || $20 !~ /^[0-9]+$/ || length($20) > 12) exit 1
            print $20
            ok = 1
        }
        END { if (!ok) exit 1 }
    ' "$1"
}

r800_uptime_seconds() {
    value=$($B cut -d. -f1 "$1") || return 1
    r800_uint "$value" || return 1
    printf '%s\n' "$value"
}

r800_clock_ticks() {
    value=$(getconf CLK_TCK 2>/dev/null) ||
        value=$($B getconf CLK_TCK 2>/dev/null) || return 1
    r800_uint "$value" && [ "$value" -gt 0 ] && [ "$value" -le 1000000 ] || return 1
    printf '%s\n' "$value"
}

r800_hwc_action() {
    # now, error observation, last frame, last recovery, process age,
    # zero-copy mode. All timestamps use monotonic uptime seconds.
    [ "$#" -eq 6 ] || return 1
    for n in "$1" "$2" "$3" "$4" "$5"; do
        r800_uint "$n" || return 1
    done
    [ "$2" -gt "$3" ] && [ "$2" -le "$1" ] &&
        [ "$4" -le "$1" ] && [ "$(( $1 - $2 ))" -ge 5 ] &&
        [ "$(( $1 - $4 ))" -ge 60 ] && [ "$5" -ge 60 ] || return 1
    case "$6" in
        0)
            if [ "$4" -gt 0 ] && [ "$3" -le "$4" ]; then
                printf '%s\n' reboot
            else
                printf '%s\n' restart
            fi
            ;;
        1|"") printf '%s\n' reboot ;; # historical default: zero-copy
        *) return 1 ;;
    esac
}
