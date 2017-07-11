#!/bin/bash -xe

# Define inputs here
bucket_name=lkjerwlkjsdf

CURL_ARGS="--fail --insecure --retry 10 --retry-delay 30"
COOKIE_FILE="/tmp/cookie.txt"

# parameters to fetch for functions
ip=$(curl --silent --fail http://169.254.169.254/latest/meta-data/local-ipv4)
local_hostname=$(curl --silent --fail http://169.254.169.254/latest/meta-data/local-hostname)

put () { # sr_api_url, #json_doc
  srr_api=$1
  json=$2
  curl $CURL_ARGS        -X PUT        -b "${COOKIE_FILE}"        -d "$json"        "${srr_api}"
}

get_local_srr_password () { # server_public_ip
  curl http://169.254.169.254/latest/meta-data/instance-id
}

sudo storreducectl server init        --admin_port=8080        --cluster_listen_port=8095        --config_server_client_port=2379        --config_server_peer_port=2380        --dev_n_shards=36        --http_port=80        --https_port=443        --n_shard_replicas=2        --force=true        --cluster_listen_interface=${ip}        ${cluster_token}

# Wait for StorReduce on server to be up
while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done
curl --fail --insecure -H 'Content-Type:application/json' -X POST -c ${COOKIE_FILE} -d '{"UserId": "srr:root", "Password": "'$(get_local_srr_password)'"}' https://${ip}:8080/api/auth/srr --retry 10 --retry-delay 30

put "https://$ip:8080/api/srr/settings" '{"hostname":"'$local_hostname','$ip'", "bucket":"'$bucket_name'"}'

sudo storreducectl server restart

# Wait for StorReduce on server to be up
while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done
