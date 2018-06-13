#!/bin/bash -xe
sudo yum install -y jq

# Define inputs here
first_server_private_ip=$1
srr_password="$2"
shard_num=$3
replica_shard_num=$4
region=$5
monitor_vm_ip=$6
num_servers=$7

if [ "$shard_num" -eq "0" ]; then
   shard_num="$((8 * ${num_servers}))"
fi

sudo storreducectl server update

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
    sudo storreducectl server init        --admin_port=8080        --cluster_listen_port=8095        --config_server_client_port=2379        --config_server_peer_port=2380        --dev_n_shards=${shard_num}        --http_port=80        --https_port=443        --n_shard_replicas=${replica_shard_num}        --force=true        --cluster_listen_interface=${ip}
    while ! sudo storreducectl cluster join --token="${cluster_token}"; do sleep 1; done
    # Wait for StorReduce on server to be up
    while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done

    # put "https://$first_server_private_ip:8080/api/srr/settings" '{"hostname":"'$local_hostname,$ip'"}'

    while ! sudo storreducectl cluster rebalance; do sleep 1; done
}

sudo docker pull storreduce/storreduce:latest

while ! curl --fail --insecure -H 'Content-Type:application/json' -X POST -c ${COOKIE_FILE} -d '{"UserId": "srr:root", "Password": "'${srr_password}'"}' https://${first_server_private_ip}:8080/api/auth/srr --retry 10 --retry-delay 30; do sleep 1; done

cluster_token="$(get_cluster_discovery_token ${first_server_public_sr_api})"

configure_server "$cluster_token"

# Configure storreduce monitor
sudo yum install -y storreduce-monitor
cd /usr/share/storreduce/filebeat
sudo storreduce-filebeat install "$monitor_vm_ip:5044"
sudo storreducectl server flags set stats_server_address "$monitor_vm_ip:9090"

sudo storreducectl server restart

# Wait for StorReduce on server to be up
while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done

sudo sed -i s/${srr_password}/xxxxx/g /var/log/cfn-init.log
sudo sed -i s/${srr_password}/xxxxx/g /var/log/cfn-init-cmd.log
sudo rm -rf ${COOKIE_FILE}