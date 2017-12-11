#!/bin/bash -xe
sudo yum install -y jq

# Define inputs here
first_server_private_ip=$1
srr_password="$2"

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

while ! curl --fail --insecure -H 'Content-Type:application/json' -X POST -c ${COOKIE_FILE} -d '{"UserId": "srr:root", "Password": "'${srr_password}'"}' https://${first_server_private_ip}:8080/api/auth/srr --retry 10 --retry-delay 30; do sleep 1; done

cluster_token="$(get_cluster_discovery_token ${first_server_public_sr_api})"

sudo storreduce-monitor --initial_cluster_discovery_token="$cluster_token"

# sudo curl -XPUT -u elastic:changeme 'localhost:9200/_xpack/security/user/elastic/_password' -H "Content-Type: application/json" -d '{
# "password" : "'"${srr_password}"'"
# }'
# sudo curl -XPUT -u elastic:"${srr_password}" 'localhost:9200/_xpack/security/user/kibana/_password' -H "Content-Type: application/json" -d '{
# "password" : "'"${srr_password}"'"
# }'

# sudo curl -XPUT -u elastic:"${srr_password}" 'localhost:9200/_xpack/security/user/logstash_system/_password' -H "Content-Type: application/json" -d '{
# "password" : "'"${srr_password}"'"
# }'

# Set Grafana password

echo "Waiting for start up to 100 seconds before continuing..."
for i in {1..50}; do 
  curl http://127.0.0.1:$GRAFANA_HOST_PORT > /dev/null 2>&1 && break || sleep 2; 
done

curl -X PUT -H "Content-Type: application/json" -d '{
  "oldPassword": "admin",
  "newPassword": "'${srr_password}'",
  "confirmNew": "'${srr_password}'"
}' http://admin:admin@127.0.0.1:3000/api/user/password

sudo rm -rf "/tmp/cookie.txt"
sudo sed -i s/${srr_password}/xxxxx/g /var/log/cfn-init.log
sudo sed -i s/${srr_password}/xxxxx/g /var/log/cfn-init-cmd.log

#####
# curl -XPUT -u elastic:changeme 'localhost:9200/_xpack/security/user/elastic/_password' -H "Content-Type: application/json" -d '{
# "password" : "'"storreduce"'"
# }'
# curl -XPUT -u elastic:"storreduce" 'localhost:9200/_xpack/security/user/kibana/_password' -H "Content-Type: application/json" -d '{
# "password" : "'"storreduce"'"
# }'

# curl -XPUT -u elastic:"storreduce" 'localhost:9200/_xpack/security/user/logstash_system/_password' -H "Content-Type: application/json" -d '{
# "password" : "'"storreduce"'"
# }'