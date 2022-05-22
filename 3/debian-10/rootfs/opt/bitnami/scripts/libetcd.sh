#!/bin/bash
#
# Bitnami etcd library

# shellcheck disable=SC1090,SC1091

# Load Generic Libraries
. /opt/bitnami/scripts/libfile.sh
. /opt/bitnami/scripts/libfs.sh
. /opt/bitnami/scripts/liblog.sh
. /opt/bitnami/scripts/libos.sh
. /opt/bitnami/scripts/libnet.sh
. /opt/bitnami/scripts/libservice.sh

# Functions

########################
# Validate settings in ETCD_* environment variables
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_validate() {
    info "Validating settings in ETCD_* env vars.."
    local error_code=0

    # Auxiliary functions
    print_validation_error() {
        error "$1"
        error_code=1
    }

    if is_boolean_yes "$ALLOW_NONE_AUTHENTICATION"; then
        warn "You set the environment variable ALLOW_NONE_AUTHENTICATION=${ALLOW_NONE_AUTHENTICATION}. For safety reasons, do not use this flag in a production environment."
    else
        is_empty_value "$ETCD_ROOT_PASSWORD" && print_validation_error "The ETCD_ROOT_PASSWORD environment variable is empty or not set. Set the environment variable ALLOW_NONE_AUTHENTICATION=yes to allow a blank password. This is only recommended for development environments."
    fi
    if is_boolean_yes "$ETCD_START_FROM_SNAPSHOT" && [[ ! -f "${ETCD_INIT_SNAPSHOTS_DIR}/${ETCD_INIT_SNAPSHOT_FILENAME}" ]]; then
        print_validation_error "You are trying to initialize etcd from a snapshot, but no snapshot was found. Set the environment variable ETCD_INIT_SNAPSHOT_FILENAME with the snapshot filename and mount it at '${ETCD_INIT_SNAPSHOTS_DIR}' directory."
    fi

    [[ "$error_code" -eq 0 ]] || return "$error_code"
}

########################
# Check if etcd is running
# Arguments:
#   None
# Returns:
#   Boolean
#########################
is_etcd_running() {
    local -r pid="$(pgrep -f "^etcd")"

    if [[ -n "$pid" ]]; then
        is_service_running "$pid"
    else
        false
    fi
}

########################
# Stop etcd
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_stop() {
    local pid
    ! is_etcd_running && return

    info "Stopping etcd"
    pid="$(pgrep -f "^etcd")"
    local counter=10
    kill "$pid"
    while [[ "$counter" -ne 0 ]] && is_service_running "$pid"; do
        sleep 1
        counter=$((counter - 1))
    done
}

########################
# Start etcd in background
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_start_bg() {
    is_etcd_running && return

    info "Starting etcd in background"
    debug_execute "etcd" &
    sleep 3
}

########################
# Obtain endpoints to connect when running 'ectdctl'
# Globals:
#   ETCD_*
# Arguments:
#   $1 - exclude current member from the list (default: false)
# Returns:
#   String
########################
etcdctl_get_endpoints() {
    local only_others=${1:-false}
    local -a endpoints=()
    local host domain port

    ip_has_valid_hostname() {
       local ip="${1:?ip is required}"
       local parent_domain="${1:?parent_domain is required}"

       # 'getent hosts $ip' can return hostnames in 2 different formats:
       #     POD_NAME.HEADLESS_SVC_DOMAIN.NAMESPACE.svc.cluster.local (using headless service domain)
       #     10-237-136-79.SVC_DOMAIN.NAMESPACE.svc.cluster.local (using POD's IP and service domain)
       # We need to discad the latter to avoid issues when TLS verification is enabled.
       [[ "$(getent hosts $ip)" = *"$parent_domain"* ]] && return 0
       return 1
    }

    hostname_has_ips() {
       local hostname="${1:?hostname is required}"
       [[ "$(getent ahosts "$hostname")" != "" ]] && return 0
       return 1
    }

    if is_boolean_yes "$ETCD_ON_K8S"; then
        # This piece of code assumes this container is used on a K8s environment
        # where etcd members are part of a statefulset that uses a headless service
        # to create a unique FQDN per member. Under these circumstances, the
        # ETCD_ADVERTISE_CLIENT_URLS env. variable is created as follows:
        #   SCHEME://POD_NAME.HEADLESS_SVC_DOMAIN:CLIENT_PORT
        #
        # Assuming this, we can extract the HEADLESS_SVC_DOMAIN and obtain
        # every available endpoint
        host="$(parse_uri "$ETCD_ADVERTISE_CLIENT_URLS" "host")"
        port="$(parse_uri "$ETCD_ADVERTISE_CLIENT_URLS" "port")"
        domain="${host#"${ETCD_NAME}."}"
        # When ETCD_CLUSTER_DOMAIN is set, we use that value instead of extracting
        # it from ETCD_ADVERTISE_CLIENT_URLS
        ! is_empty_value "$ETCD_CLUSTER_DOMAIN" && domain="$ETCD_CLUSTER_DOMAIN"
        # Depending on the K8s distro & the DNS plugin, it might need
        # a few seconds to associate the POD(s) IP(s) to the headless svc domain
        if retry_while "hostname_has_ips $domain"; then
            for ip in $(getent ahosts "$domain" | awk '{print $1}' | uniq); do
                if retry_while "ip_has_valid_hostname $ip $domain"; then
                    h="$(getent hosts "$ip" | awk '{print $2}')"
                    if ! { [[ $only_others = true ]] && [[ "$h" = "$host" ]]; }; then
                        endpoints+=("${h}:${port}")
                    fi
                fi
            done
        fi
        echo "${endpoints[*]}" | tr ' ' ','
    else
        echo ""
    fi
    echo "${endpoints[*]}" | tr ' ' ','
}

########################
# Obtain etcdctl authentication flags to use
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   Array with extra flags to use for authentication
#########################
etcdctl_auth_flags() {
    local -a authFlags=()

    ! is_empty_value "$ETCD_ROOT_PASSWORD" && authFlags+=("--user" "root:$ETCD_ROOT_PASSWORD")
    if [[ $ETCD_AUTO_TLS = true ]]; then
        authFlags+=("--cert" "${ETCD_DATA_DIR}/fixtures/client/cert.pem" "--key" "${ETCD_DATA_DIR}/fixtures/client/key.pem")
    else
        [[ -f "$ETCD_CERT_FILE" ]] && [[ -f "$ETCD_KEY_FILE" ]] && authFlags+=("--cert" "$ETCD_CERT_FILE" "--key" "$ETCD_KEY_FILE")
        [[ -f "$ETCD_TRUSTED_CA_FILE" ]] && authFlags+=("--cacert" "$ETCD_TRUSTED_CA_FILE")
    fi
    echo "${authFlags[@]}"
}

########################
# Stores etcd member ID in the data directory
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
etcd_store_member_id() {
    local -a extra_flags

    read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
    extra_flags+=("--endpoints=$(etcdctl_get_endpoints)")
    if retry_while "etcdctl ${extra_flags[*]} member list" >/dev/null 2>&1; then
        while [[ ! -s "${ETCD_DATA_DIR}/member_id" ]]; do
            # We use 'stdbuf' to ensure memory buffers are flushed to disk
            # so we reduce the chances that the "member_id" file is not created.
            # ref: https://www.gnu.org/software/coreutils/manual/html_node/stdbuf-invocation.html#stdbuf-invocation
            stdbuf -oL etcdctl "${extra_flags[@]}" member list | grep -w "$ETCD_ADVERTISE_CLIENT_URLS" | awk -F "," '{ print $1}' > "${ETCD_DATA_DIR}/member_id" || true
        done
        debug "Stored member ID: $(cat "${ETCD_DATA_DIR}/member_id")"
    fi
}

########################
# Configure etcd RBAC (do not confuse with K8s RBAC)
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
etcd_configure_rbac() {
    info "Enabling etcd authentication"

    ! is_etcd_running && etcd_start_bg
    read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
    extra_flags+=("--endpoints=$(etcdctl_get_endpoints)")
    if retry_while "etcdctl ${extra_flags[*]} member list" >/dev/null 2>&1; then
        debug_execute etcdctl "${extra_flags[@]}" user add root --interactive=false <<< "$ETCD_ROOT_PASSWORD"
        debug_execute etcdctl "${extra_flags[@]}" user grant-role root root
        debug_execute etcdctl "${extra_flags[@]}" auth enable
    fi
    etcd_stop
}

########################
# Checks if the member was successfully removed from the cluster
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
########################
was_etcd_member_removed() {
    local return_value=0

    if grep -sqE "^Member[[:space:]]+[a-z0-9]+\s+removed\s+from\s+cluster\s+[a-z0-9]+$" "${ETCD_VOLUME_DIR}/member_removal.log"; then
        debug "Removal was properly recorded in member_removal.log"
        rm -rf "${ETCD_DATA_DIR:?}/"*
    elif [[ ! -d "${ETCD_DATA_DIR}/member/snap" ]] && [[ ! -f "$ETCD_DATA_DIR/member_id" ]]; then
        debug "Missing member data"
        rm -rf "${ETCD_DATA_DIR:?}/"*
    else
        return_value=1
    fi
    rm -f "${ETCD_VOLUME_DIR}/member_removal.log"
    return $return_value
}

########################
# Checks if etcd needs to bootstrap a new cluster
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   Boolean
########################
is_new_etcd_cluster() {
    [[ "$ETCD_INITIAL_CLUSTER_STATE" = "new" ]] && [[ "$ETCD_INITIAL_CLUSTER" = *"$ETCD_INITIAL_ADVERTISE_PEER_URLS"* ]]
}

########################
# Checks if there are enough active members, will also set ETCD_ACTIVE_ENDPOINTS
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   Boolean
########################
is_healthy_etcd_cluster() {
    local return_value=0
    local active_endpoints=0
    local -a extra_flags active_endpoints_array
    local host port

    read -r -a endpoints_array <<< "$(tr ',;' ' ' <<< "$(etcdctl_get_endpoints)")"
    local -r cluster_size=${#endpoints_array[@]}
    host="$(parse_uri "$ETCD_ADVERTISE_CLIENT_URLS" "host")"
    port="$(parse_uri "$ETCD_ADVERTISE_CLIENT_URLS" "port")"
    for e in "${endpoints_array[@]}"; do
        read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
        extra_flags+=("--endpoints=$e")
        if [[ "$e" != "$host:$port" ]] && etcdctl endpoint health "${extra_flags[@]}" >/dev/null 2>&1; then
            debug "$e endpoint is active"
            ((active_endpoints++))
            active_endpoints_array+=("$e")
        fi
    done
    ETCD_ACTIVE_ENDPOINTS=$(echo "${active_endpoints_array[*]}" | tr ' ' ',')
    export ETCD_ACTIVE_ENDPOINTS

    if is_boolean_yes "$ETCD_DISASTER_RECOVERY"; then
        if [[ -f "/snapshots/.disaster_recovery" ]]; then
            # Remove current node from the ones that need to recover
            remove_in_file "/snapshots/.disaster_recovery" "$host:$port" || true
            # Remove nodes that do not exist anymore from the ones that need to recover
            read -r -a recovery_array <<< $(tr '\n' ' ' < "/snapshots/.disaster_recovery")
            for r in "${recovery_array[@]}"; do
                if [[ ! " ${endpoints_array[*]} " =~ " $r " ]]; then
                    remove_in_file "/snapshots/.disaster_recovery" "$r" || true
                fi
            done
            if [[ $(wc -w < "/snapshots/.disaster_recovery") -eq 0 ]]; then
                debug "Last member to recover from the disaster!"
                rm "/snapshots/.disaster_recovery"
            fi
            return_value=1
        else
            if [[ $active_endpoints -lt $(((cluster_size + 1)/2)) ]]; then
                debug "There are no enough active endpoints!"
                for e in "${endpoints_array[@]}"; do
                    [[ "$e" != "$host:$port" ]] && [[ "$e" != ":$port" ]] && echo "$e" >> "/snapshots/.disaster_recovery"
                done
                return_value=1
            fi
        fi
    else
        if [[ $active_endpoints -lt $(((cluster_size + 1)/2)) ]]; then
            debug "There are no enough active endpoints!"
            return_value=1
        fi
    fi

    return $return_value
}

########################
# Recalculate initial cluster
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   String
########################
recalculate_initial_cluster() {
    local -a endpoints_array initial_members
    local domain host member_host member_port member_id port scheme

    if is_boolean_yes "$ETCD_ON_K8S"; then
        read -r -a endpoints_array <<< "$(tr ',;' ' ' <<< "$(etcdctl_get_endpoints)")"
        # This piece of code assumes this container is used on a K8s environment
        # where etcd members are part of a statefulset that uses a headless service
        # to create a unique FQDN per member. Under these circumstances, the
        # ETCD_INITIAL_ADVERTISE_PEER_URLS are created as follows:
        #   SCHEME://POD_NAME.HEADLESS_SVC_DOMAIN:PEER_PORT
        #
        # Assuming this, we can extract the HEADLESS_SVC_DOMAIN
        host="$(parse_uri "$ETCD_INITIAL_ADVERTISE_PEER_URLS" "host")"
        scheme="$(parse_uri "$ETCD_INITIAL_ADVERTISE_PEER_URLS" "scheme")"
        port="$(parse_uri "$ETCD_INITIAL_ADVERTISE_PEER_URLS" "port")"
        domain="${host#"${ETCD_NAME}."}"
        # When ETCD_CLUSTER_DOMAIN is set, we use that value instead of extracting
        # it from ETCD_INITIAL_ADVERTISE_PEER_URLS
        ! is_empty_value "$ETCD_CLUSTER_DOMAIN" && domain="$ETCD_CLUSTER_DOMAIN"
        for e in "${endpoints_array[@]}"; do
             member_host="$(parse_uri "$scheme://$e" "host")"
             member_port="$(parse_uri "$scheme://$e" "port")"
             member_id=${e%".$domain:$member_port"}
             initial_members+=("${member_id}=${scheme}://${member_host}:$port")
        done
        echo "${initial_members[*]}" | tr ' ' ','
    else
        # Nothing to do
        echo "$ETCD_INITIAL_CLUSTER"
    fi
}

########################
# Ensure etcd is initialized
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
#########################
etcd_initialize() {
    local -a extra_flags initial_members
    local domain

    info "Initializing etcd"
    read -r -a initial_members <<< "$(tr ',;' ' ' <<< "$ETCD_INITIAL_CLUSTER")"
    if is_mounted_dir_empty "$ETCD_DATA_DIR"; then
        info "There is no data from previous deployments"
        if [[ ${#initial_members[@]} -gt 1 ]]; then
            if is_new_etcd_cluster; then
                info "Bootstrapping a new cluster"
                if is_boolean_yes "$ETCD_ON_K8S"; then
                    debug "Waiting for the headless svc domain to have an IP per initial member in the cluster"
                    if is_empty_value "$ETCD_CLUSTER_DOMAIN"; then
                        # This piece of code assumes this container is used on a K8s environment
                        # where etcd members are part of a statefulset that uses a headless service
                        # to create a unique FQDN per member. Under these circumstances, the
                        # ETCD_INITIAL_ADVERTISE_PEER_URLS are created as follows:
                        #   SCHEME://POD_NAME.HEADLESS_SVC_DOMAIN:PEER_PORT
                        #
                        # Assuming this, we can extract the HEADLESS_SVC_DOMAIN
                        host="$(parse_uri "$ETCD_INITIAL_ADVERTISE_PEER_URLS" "host")"
                        domain="${host#"${ETCD_NAME}."}"
                    else
                        # When ETCD_CLUSTER_DOMAIN is set, we use that value instead of extracting
                        # it from ETCD_INITIAL_ADVERTISE_PEER_URLS
                        domain="$ETCD_CLUSTER_DOMAIN"
                    fi
                    hostname_has_N_ips() {
                       local -r hostname="${1:?hostname is required}"
                       local -r n=${2:?number of ips is required}
                       [[ $(getent ahosts "$hostname" | awk '{print $1}' | uniq | wc -l) -eq $n ]] && return 0
                       return 1
                    }
                    if ! retry_while "hostname_has_N_ips $domain ${#initial_members[@]}"; then
                        error "Headless service domain does not have an IP per initial member in the cluster"
                        exit 1
                    fi
                fi
            else
                info "Adding new member to existing cluster"
                ensure_dir_exists "$ETCD_DATA_DIR"
                add_self_to_cluster
            fi
        fi
        if is_boolean_yes "$ETCD_START_FROM_SNAPSHOT"; then
            if [[ -f "${ETCD_INIT_SNAPSHOTS_DIR}/${ETCD_INIT_SNAPSHOT_FILENAME}" ]]; then
                info "Restoring snapshot before initializing etcd cluster"
                local -a restore_args=("--data-dir" "$ETCD_DATA_DIR")
                if [[ ${#initial_members[@]} -gt 1 ]]; then
                    ETCD_INITIAL_CLUSTER="$(recalculate_initial_cluster)"
                    export ETCD_INITIAL_CLUSTER
                    restore_args+=(
                        "--name" "$ETCD_NAME"
                        "--initial-cluster" "$ETCD_INITIAL_CLUSTER"
                        "--initial-cluster-token" "$ETCD_INITIAL_CLUSTER_TOKEN"
                        "--initial-advertise-peer-urls" "$ETCD_INITIAL_ADVERTISE_PEER_URLS"
                    )
                fi
                debug_execute etcdctl snapshot restore "${ETCD_INIT_SNAPSHOTS_DIR}/${ETCD_INIT_SNAPSHOT_FILENAME}" "${restore_args[@]}"
            else
                error "There was no snapshot to restore!"
                exit 1
            fi
        else
            if [[ ${#initial_members[@]} -gt 1 ]]; then
                # When there's more than one etcd replica, RBAC should be only enabled in one member
                if ! is_empty_value "$ETCD_ROOT_PASSWORD" && [[ "$ETCD_INITIAL_CLUSTER_STATE" = "new" ]] && [[ "${initial_members[0]}" = *"$ETCD_INITIAL_ADVERTISE_PEER_URLS"* ]]; then
                    etcd_configure_rbac
                else
                    debug "Skipping RBAC configuration in member $ETCD_NAME"
                fi
            else
                ! is_empty_value "$ETCD_ROOT_PASSWORD" && etcd_configure_rbac
            fi
        fi
    else
        info "Detected data from previous deployments"
        if [[ $(stat -c "%a" "$ETCD_DATA_DIR") != *700 ]]; then
            debug "Setting data directory permissions to 700 in a recursive way (required in etcd >=3.4.10)"
            debug_execute chmod -R 700 "$ETCD_DATA_DIR" || true
        fi
        if [[ ${#initial_members[@]} -gt 1 ]]; then
            info "The member will try to join the cluster by it's own"
            export ETCD_INITIAL_CLUSTER_STATE=existing
        fi
    fi

    # Avoid exit code of previous commands to affect the result of this function
    true
}

########################
# Add self to cluster if not
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   None
#########################
add_self_to_cluster() {
    local -a extra_flags
    read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
    # is_healthy_etcd_cluster will also set ETCD_ACTIVE_ENDPOINTS
    while ! is_healthy_etcd_cluster; do
        warn "Cluster not healthy, not adding self to cluster for now, keeping trying..."
        sleep 10
    done

    # only send req to healthy nodes

    if is_empty_value "$(get_member_id)"; then
        extra_flags+=("--endpoints=${ETCD_ACTIVE_ENDPOINTS}" "--peer-urls=$ETCD_INITIAL_ADVERTISE_PEER_URLS")
        while ! etcdctl member add "$ETCD_NAME" "${extra_flags[@]}"  | grep "^ETCD_" > "$ETCD_NEW_MEMBERS_ENV_FILE"; do
            warn "Failed to add self to cluster, keeping trying..."
            sleep 10
        done
        replace_in_file "$ETCD_NEW_MEMBERS_ENV_FILE" "^" "export "
        sync -d "$ETCD_NEW_MEMBERS_ENV_FILE"
    else
        info "Node already in cluster"
    fi
    info "Loading env vars of existing cluster"
    . "$ETCD_NEW_MEMBERS_ENV_FILE"
}

########################
# Get this node's member_id in cluster, if not in cluster return empty string
# Globals:
#   ETCD_*
# Arguments:
#   None
# Returns:
#   String
#########################
get_member_id() {
    local ret
    local -a extra_flags
    read -r -a extra_flags <<< "$(etcdctl_auth_flags)"
    extra_flags+=("--endpoints=${ETCD_ACTIVE_ENDPOINTS}")
    ret=$(etcdctl "${extra_flags[@]}" member list | grep -w "$ETCD_INITIAL_ADVERTISE_PEER_URLS" | awk -F "," '{ print $1}')
    # if not return zero
    info "member id: $ret"
    if [[ $? -ne 0 ]]; then
        echo ""
    else
        echo "$ret"
    fi
}