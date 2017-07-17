#!/bin/bash -xe
sudo yum install -y jq

# Define inputs here
first_server_private_ip=$1
first_server_instance_id=$2
load_balancer_DNS=$3

# Reformed inputs
first_server_public_sr_api="https://${first_server_private_ip}:8080/api"

# the password is server_public_ip.
#-> Create a password input to the autoscaling group
#-> Pull the public ip from the first instance and send to autoscaling group
#-> Get each instance to poll for the cluster token 
#-> configure_server_amazon

CURL_ARGS="--fail --insecure --retry 10 --retry-delay 30"
COOKIE_FILE="/tmp/cookie.txt"

# parameters to fetch for functions
ip=$(curl --silent --fail http://169.254.169.254/latest/meta-data/local-ipv4)
local_hostname=$(curl --silent --fail http://169.254.169.254/latest/meta-data/local-hostname)

get_cluster_discovery_token () { # sr_api_url
  srr_api=$1
  while ! cluster_info=$(curl $CURL_ARGS       -X GET      -b "${COOKIE_FILE}"        "${srr_api}/srr/cluster/current"); do sleep 1; done
  echo $(echo $cluster_info | jq -r '.ClusterDiscoveryToken' )
}

put () { # sr_api_url, #json_doc
  srr_api=$1
  json=$2
  while ! curl $CURL_ARGS -X PUT        -b "${COOKIE_FILE}"        -d "$json"       "${srr_api}"; do sleep 1; done
}

configure_server () { # server_public_ip, cluster_token
    cluster_token=$1
    sudo storreducectl server init        --admin_port=8080        --cluster_listen_port=8095        --config_server_client_port=2379        --config_server_peer_port=2380        --dev_n_shards=36        --http_port=80        --https_port=443        --n_shard_replicas=2        --force=true        --cluster_listen_interface=${ip}
    while ! sudo storreducectl cluster join --token="${cluster_token}"; do sleep 1; done
    # Wait for StorReduce on server to be up
    while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done

    put "https://$ip:8080/api/srr/settings" '{"hostname":"'$load_balancer_DNS'"}'

    #while ! sudo storreducectl cluster restart; do sleep 1; done

    while ! sudo storreducectl cluster leave; do sleep 1; done
}

get_local_srr_password () { # server_public_ip
  curl http://169.254.169.254/latest/meta-data/instance-id
}

while ! curl --fail --insecure -H 'Content-Type:application/json' -X POST -c ${COOKIE_FILE} -d '{"UserId": "srr:root", "Password": "'${first_server_instance_id}'"}' https://${first_server_private_ip}:8080/api/auth/srr --retry 10 --retry-delay 30; do sleep 1; done

cluster_token="$(get_cluster_discovery_token ${first_server_public_sr_api})"

configure_server "$cluster_token"

# sudo storreducectl cluster restart -f
# Error restarting StorReduce on server 10.0.22.21: Error creating SSH client: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain
# TODO: Generate key and install on all the hosts