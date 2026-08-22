#!/bin/sh
# Verdix app entrypoint.
# Runs as root just long enough to make the bind-mounted Suricata log and
# config paths readable by appuser, then execs into the real process as
# appuser — nothing application-level ever runs as root.
#
# eve.json's owning group is not predictable across distros/install methods
# (native apt/dnf packages typically run Suricata as a dedicated `suricata`
# user/group; some installs leave logs world-readable under root:root;
# Security Onion and SELKS run Suricata inside their own managed containers
# with their own UID mapping). This replaces the old manual
# `stat -c "%g"` + docker-compose.override.yml `group_add` workflow
# (formerly DEPLOYMENT.md step B5) with automatic per-boot detection.
set -eu

# Shared tail end of group detection: given a GID already known to be
# correct for $path (by whichever probe determined it), join appuser to the
# group that owns it (creating one if none claims that GID yet), then retest
# readability as appuser. Called from both branches of check_and_fix below —
# the branch where appuser itself could determine the GID (path traversable,
# file itself unreadable), and the branch where root had to determine it
# because appuser couldn't even reach the path (a closed parent directory).
join_group_and_retest() {
    path="$1"
    label="$2"
    gid="$3"

    group_name=$(getent group "$gid" | cut -d: -f1)

    if [ -z "$group_name" ]; then
        # No group in the image already claims this GID — create one.
        group_name="vx_${label}"
        groupadd -g "$gid" "$group_name"
        echo "[vx-entrypoint] $label: $path is gid $gid, no group claims it — created '$group_name'."
    else
        # A group already claims this GID (e.g. GID 4 is "adm" in the base
        # Debian image) — reuse it, since groupadd would fail with "GID
        # already exists".
        echo "[vx-entrypoint] $label: $path is gid $gid, already '$group_name' in this image — reusing it."
    fi

    usermod -aG "$group_name" appuser
    echo "[vx-entrypoint] $label: joined appuser to '$group_name'."

    if gosu appuser test -r "$path"; then
        echo "[vx-entrypoint] $label: $path now readable via '$group_name'."
    else
        echo "[vx-entrypoint] ERROR: appuser still cannot read $path after joining group '$group_name' (gid $gid)." >&2
        echo "[vx-entrypoint] This is usually an ordinary parent-directory permission mode on a local bind mount, NFS root_squash, SELinux (check 'ls -Z $path' on the host), or a POSIX ACL beyond the owning group (check 'getfacl $path')." >&2
        echo "[vx-entrypoint] Fix the source permissions or grant appuser (uid 38317) explicit read access. The application will start and report this on its health screen — restart the container once permissions are fixed." >&2
    fi
}

# Fast path: if appuser can already read the path (world-readable mount),
# there's nothing to do. Only chase group membership on failure.
check_and_fix() {
    path="$1"
    label="$2"

    # Existence and readability are probed as appuser, not root. On an NFS
    # export with root_squash (the common case — see docs/DEPLOYMENT.md
    # Topology 2), the server maps uid 0 to `nobody`, so root's own `test -e`
    # can return false for a mount that genuinely exists and is readable to
    # appuser. root_squash only squashes uid 0; appuser is unaffected, which
    # is exactly why probing as appuser instead of root avoids the false
    # negative.
    #
    # `stat` instead of `test -e` here so a genuinely missing path can be
    # told apart from one that exists but isn't traversable/statable by
    # appuser (a directory-level permission block, distinct from the
    # file-level unreadable case handled by the `test -r` probe below) —
    # GNU coreutils' stat gives distinct, English (POSIX-locale) stderr text
    # for the two cases, which the Python-side equivalent (os.path.isfile +
    # os.access) can't do for shell without this.
    if ! stat_out=$(gosu appuser stat "$path" 2>&1); then
        case "$stat_out" in
            *"Permission denied"*)
                # The path exists but appuser can't reach it at all — most
                # often an ordinary parent-directory mode on a local bind
                # mount (0750/0770, owned by a group appuser isn't in, not
                # world-searchable): this is exactly how a stock apt/dnf
                # Suricata install leaves /var/log/suricata and
                # /etc/suricata. Unlike the root_squash case above, root has
                # no equivalent block reading a local filesystem's metadata,
                # so root can determine the GID directly here and the
                # group-join can proceed without appuser ever having been
                # able to see the path.
                echo "[vx-entrypoint] $label: $path exists but appuser cannot access it (permission denied) — probing its group as root."
                if ! gid=$(stat -c '%g' "$path" 2>&1); then
                    echo "[vx-entrypoint] $label: root could not determine $path's group either ($gid) — skipping. Check the export's root_squash setting, SELinux context ('ls -Z $path' on the host), or a POSIX ACL on a parent directory ('getfacl')."
                    return 0
                fi
                join_group_and_retest "$path" "$label" "$gid"
                ;;
            *)
                echo "[vx-entrypoint] $label: $path does not exist — skipping. If this path should exist, check the mount."
                ;;
        esac
        return 0
    fi

    if gosu appuser test -r "$path"; then
        echo "[vx-entrypoint] $label: $path already readable by appuser — skipping group detection."
        return 0
    fi

    # Same root_squash reasoning as the existence/readability probes above:
    # root reading the gid here would hit the same false failure once group
    # detection actually needs to run. Guarded against a TOCTOU: the path
    # could go unreadable between the test -r above and this stat, and under
    # set -eu an unguarded failure here would abort the whole script with
    # only stat's raw stderr as a diagnostic — the app never gets a chance
    # to start and report it.
    if ! gid=$(gosu appuser stat -c '%g' "$path" 2>&1); then
        echo "[vx-entrypoint] $label: could not stat $path to detect its group ($gid) — skipping group detection."
        return 0
    fi

    join_group_and_retest "$path" "$label" "$gid"
}

check_and_fix "${VX_EVE_LOG_PATH:-/host/suricata/logs/eve.json}" "logs"
check_and_fix "${VX_SURICATA_CONFIG_PATH:-/host/suricata/config/suricata.yaml}" "config"

exec gosu appuser "$@"
