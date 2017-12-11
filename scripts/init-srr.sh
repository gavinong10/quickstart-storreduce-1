#!/bin/bash -xe

# Define inputs here
bucket_name=$1
srr_license="$2"
srr_password="$3"
shard_num=$4
replica_shard_num=$5
hostname=$6
load_balancer_DNS=$7
load_balancer_name=$8
region=$9
monitor_vm_ip=${10}
num_servers=${11}

if [ "$shard_num" -eq "0" ]; then
   shard_num="$((8 * ${num_servers}))"
fi

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

sudo docker pull storreduce/storreduce:latest

sudo storreducectl server init        --admin_port=8080        --cluster_listen_port=8095        --config_server_client_port=2379        --config_server_peer_port=2380        --dev_n_shards=${shard_num}        --http_port=80        --https_port=443        --n_shard_replicas=${replica_shard_num}        --force=true        --cluster_listen_interface=${ip}       ${cluster_token}

# Wait for StorReduce on server to be up
while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done
curl --fail --insecure -H 'Content-Type:application/json' -X POST -c ${COOKIE_FILE} -d '{"UserId": "srr:root", "Password": "'$(get_local_srr_password)'"}' https://${ip}:8080/api/auth/srr --retry 10 --retry-delay 30

curl --fail --insecure -H 'Content-Type:application/json' -X POST -b ${COOKIE_FILE} -d '{"NewPassword": "'$srr_password'"}' https://${ip}:8080/api/srr/id/root/password --retry 10 --retry-delay 30

if [ -z "$hostname" ]; then
  put "https://$ip:8080/api/srr/settings" '{"hostname":"'$load_balancer_DNS,$hostname'", "bucket":"'"$bucket_name"'", "license": "'"$srr_license"'"}'
else
  put "https://$ip:8080/api/srr/settings" '{"hostname":"'$load_balancer_DNS'", "bucket":"'"$bucket_name"'", "license": "'"$srr_license"'"}'
fi

# Configure storreduce monitor
sudo yum install -y storreduce-monitor
cd /usr/share/storreduce/filebeat
sudo storreduce-filebeat install "$monitor_vm_ip:5044"
sudo storreducectl server flags set stats_server_address "$monitor_vm_ip:9090"

sudo storreducectl server restart

# Wait for StorReduce on server to be up
while ! curl --insecure --fail https://${ip}:8080 > /dev/null 2>&1; do sleep 1; done

aws elb register-instances-with-load-balancer --load-balancer-name="$load_balancer_name" --instances=`curl http://169.254.169.254/latest/meta-data/instance-id` --region="$region"

#trim
#replace " with \\"
#replace \n with \\n",\n"
#append at start and finish character "

sudo sed -i s/${srr_password}/xxxxx/g /var/log/cfn-init.log
sudo sed -i s/${srr_password}/xxxxx/g /var/log/cfn-init-cmd.log
sudo rm -rf ${COOKIE_FILE}