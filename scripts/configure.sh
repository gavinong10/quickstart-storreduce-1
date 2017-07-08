#!/bin/bash -xe

# Define inputs here
first_server_private_ip=

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
  cluster_info=$(curl $CURL_ARGS \
       -X GET \
       -b "${COOKIE_FILE}" \
       "${srr_api}/srr/cluster/current")
  echo $(echo $cluster_info | jq -r '.ClusterDiscoveryToken' )
}

put () { # sr_api_url, #json_doc
  srr_api=$1
  json=$2
  curl $CURL_ARGS \
       -X PUT \
       -b "${COOKIE_FILE}" \
       -d "$json" \
       "${srr_api}"
}

configure_server () { # server_public_ip, cluster_token
    cluster_token=$1
    put "https://$ip:8080/api/srr/cluster/current/server/current" "{\"ClusterDiscoveryToken\":\"$cluster_token\"}"
    put "https://$ip:8080/api/srr/settings" "{\"hostname\":\"$local_hostname,$ip\"}"
}

get_local_srr_password () { # server_public_ip
  curl http://169.254.169.254/latest/meta-data/instance-id
}

curl --fail --insecure -H \"Content-Type: application/json\" -X POST -c ${COOKIE_FILE} -d \"{\\\"UserId\\\": \\\"srr:root\\\", \\\"Password\\\": \\\"$(get_local_srr_password)\\\"}\" https://${ip}:8080/api/auth/srr --retry 10 --retry-delay 30

cluster_token=$(get_cluster_discovery_token "${first_server_public_sr_api}")

sudo storreducectl server init \
        --admin_port=8080 \
        --cluster_listen_port=8095 \
        --config_server_client_port=2379 \
        --config_server_peer_port=2380 \
        --dev_n_shards=36 \
        --http_port=80 \
        --https_port=443 \
        --n_shard_replicas=2 \
        --force=true \
        --cluster_listen_interface=${ip} \
        ${cluster_token}

configure_server $cluster_token

# TODO: Rebalance and restart cluster after setup

"#!\/bin\/bash -xe\n",

"# Define inputs here\n",
"first_server_private_ip=\n",

"# Reformed inputs\n",
"first_server_public_sr_api=\"https:\/\/${first_server_private_ip}:8080\/api\"\n",

"# the password is server_public_ip.\n",
"#-> Create a password input to the autoscaling group\n",
"#-> Pull the public ip from the first instance and send to autoscaling group\n",
"#-> Get each instance to poll for the cluster token \n",
"#-> configure_server_amazon\n",

"CURL_ARGS=\"--fail --insecure --retry 10 --retry-delay 30\"\n",
"COOKIE_FILE=\"\/tmp\/cookie.txt\"\n",

"# parameters to fetch for functions\n",
"ip=$(curl --silent --fail http:\/\/169.254.169.254\/latest\/meta-data\/local-ipv4)\n",
"local_hostname=$(curl --silent --fail http:\/\/169.254.169.254\/latest\/meta-data\/local-hostname)\n",

"get_cluster_discovery_token () { # sr_api_url\n",
"  srr_api=$1\n",
"  cluster_info=$(curl $CURL_ARGS \\\n",
"       -X GET \\\n",
"       -b \"${COOKIE_FILE}\" \\\n",
"       \"${srr_api}\/srr\/cluster\/current\")\n",
"  echo $(echo $cluster_info | jq -r '.ClusterDiscoveryToken' )\n",
"}\n",

"put () { # sr_api_url, #json_doc\n",
"  srr_api=$1\n",
"  json=$2\n",
"  curl $CURL_ARGS \\\n",
"       -X PUT \\\n",
"       -b \"${COOKIE_FILE}\" \\\n",
"       -d \"$json\" \\\n",
"       \"${srr_api}\"\n",
"}\n",

"configure_server () { # server_public_ip, cluster_token\n",
"    cluster_token=$1\n",
"    put \"https:\/\/$ip:8080\/api\/srr\/cluster\/current\/server\/current\" \"{\\\"ClusterDiscoveryToken\\\":\\\"$cluster_token\\\"}\"\n",
"    put \"https:\/\/$ip:8080\/api\/srr\/settings\" \"{\\\"hostname\\\":\\\"$local_hostname,$ip\\\"}\"\n",
"}\n",

"get_local_srr_password () { # server_public_ip\n",
"  curl http:\/\/169.254.169.254\/latest\/meta-data\/instance-id\n",
"}\n",

"curl --fail --insecure -H \\\"Content-Type: application\/json\\\" -X POST -c ${COOKIE_FILE} -d \\\"{\\\\\\\"UserId\\\\\\\": \\\\\\\"srr:root\\\\\\\", \\\\\\\"Password\\\\\\\": \\\\\\\"$(get_local_srr_password)\\\\\\\"}\\\" https:\/\/${ip}:8080\/api\/auth\/srr --retry 10 --retry-delay 30\n",

"cluster_token=$(get_cluster_discovery_token \"${first_server_public_sr_api}\")\n",

"configure_server $cluster_token"

{
  "admin_cert": "-----BEGIN CERTIFICATE-----\nMIIC/jCCAeagAwIBAgIQNzbA9y24Wii29wRm0qrzqDANBgkqhkiG9w0BAQsFADAS\nMRAwDgYDVQQKEwdBY21lIENvMCAXDTE3MDcwNTE4MjA0MloYDzIxMTcwNjExMTgy\nMDQyWjASMRAwDgYDVQQKEwdBY21lIENvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAxdoK3s5w+FSFNawTTh08EQnNh1HS7C8I6RwbhMCjNbXOHlU+tWRG\nF2zOjBbf+IGzzPcsOYgsWrEZ/9Y1/jBijRMNxsrfdKvoVOCw5AZHn+jKX/L6uXQ9\n5b1gnlwHHVh/+JjDHy+0Yu/+2fexzHQwyHLPXrKeIDNZ8KN8lG1Jt+XctDS2+Q52\ny+MK7ynopm3sr6ceRhYUf9MXlGemzpfU6C8teSPcEqBfSBh6cC5pBXgUNfIGHPsZ\nn+PC3EYS3c9sSjqcJLCKaplfeonD64dZMoy/SJV4rtyona+o35xgz51qoV+9SQfr\n+CzoNbgoQGL3nkh/gcL8kFWf8gjPYinxYQIDAQABo04wTDAOBgNVHQ8BAf8EBAMC\nAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREE\nDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAKCFwyZAPEWCw7QgNzvy\nbHzQGcxkDksKJvaySFs7/qSRGKJjXIpBw2lzb98AuuVwN6qbcEQWzL3aqHQ5526L\nByNy7qLJEUv4DW+bSx5bmURtKGz7mQP7NSwmEiOF8u+Bl5vfLdExx5/rs9YGLKV+\nxCSK0FWSC7G0G0//Cdq0CPhcH+ItLd2YU6P2XM2YG9OnDglTh+FXHFum3fC3Q/rU\nGkvip7kUUiTX0DRmIdLSksKR65IEgQhnQuUA5PVRSGuXczt7Ry4EGt/qXFkkW+Pl\nkvFsB0hAK599f7E3qpT430m2Vx1bXNXMo+3RADUAku9QcLGhRKad+HtLCfyUhhcv\nSdE=\n-----END CERTIFICATE-----\n",
  "admin_disable_https": false,
  "admin_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAxdoK3s5w+FSFNawTTh08EQnNh1HS7C8I6RwbhMCjNbXOHlU+\ntWRGF2zOjBbf+IGzzPcsOYgsWrEZ/9Y1/jBijRMNxsrfdKvoVOCw5AZHn+jKX/L6\nuXQ95b1gnlwHHVh/+JjDHy+0Yu/+2fexzHQwyHLPXrKeIDNZ8KN8lG1Jt+XctDS2\n+Q52y+MK7ynopm3sr6ceRhYUf9MXlGemzpfU6C8teSPcEqBfSBh6cC5pBXgUNfIG\nHPsZn+PC3EYS3c9sSjqcJLCKaplfeonD64dZMoy/SJV4rtyona+o35xgz51qoV+9\nSQfr+CzoNbgoQGL3nkh/gcL8kFWf8gjPYinxYQIDAQABAoIBAQC36c9g/ZWVwTty\ngNoRKqvDStF6kFz4n2AxEKej503Ph4hqOeNoyiU9cS8umbToU+jHBpxdfm98flQk\ntQLLnj591NBhkgPVeFcnTxYfYJcD1mkId90Itz0yaa9+hR038iRC+f2m57lOnrjP\n9KeZ3gfazJ5m8LJ8TD+2qMINVunHvohdCp002wWKY0OapAxAPpzG2OXDrhnnuvFg\nrOhZMzxcORHQjUJ2snIya218Q3qeNeQ4e90sCbpp6HDd2jgc5a0mJ+JvFDueVd0j\n044LW2NyR1BVhhz+Bkw3aDi3KqHXofFdArPMf+xvAPGlu+0OLWsmQsNZG39M7nPW\nepiO2BKBAoGBAM7dfeStjxrA/uXeBWDwTEy6Rlgs84LKVjDG7KGQT+uFBLdTLhry\nyH/D8HHoIB+VuXeSt6ni8kXhPOF9xyZdmJ7NrZ3xJLDuFATqAbsXkiFJ1b3EW3g6\ny5iKvjTA8eApzkHJOKPMWdxGiK/aTWr44UdaR/g6Rl6zlugNGVCcRAhNAoGBAPTY\ne77VGC0fdkGmpI007QaA737xjPI8JALkWQ/oeRrXbV6Krtd2sPCbdqp4UY+XAhKc\nCIxmyNNCQPkTrt8XTVFrp0eX71A/XSHYGdPIlsp1h0qMO/DnkFShZaLrHaOznDls\nHxhY7bIsbMgUOXo8iWpB/mdcENYJMn65I1aGwtdlAoGBAJH6HQfNLgn8HSPK69K/\nX6hZXqCEgAZQkEf1aDCOrMcPZAeWDBf6MWBvvXI0Es8XEfz+LNsWik6jphmdb3Z0\nX+nYTGcDLxgnuTrKgxQqivUwrEMwmDecjeWEKrsBWO4Nsj4cJ/r2jobxwy0NCMqu\n/BIk9FqHjPbxFlGERNPsodmVAoGAQcLLKawOPEBRAL0DQTHP34lNyeiSlJT2jxhJ\nm24y6LSnmVbiMticGWOH8a0zKr/CPMFPwnXwxlzrGnrg4uZdS9sAKMhz7De4idiC\nx1D+vw3l8m3Lw55OM4zNwX4ojck10m5pw55O6SXpaauU7HHJ7pIfBB/EHdiGiWas\nSRcUyckCgYAw3uNIcRrs8l78uGMBBAtfoMZzmk9GnW0oG6O8MzGwpBnz+vqnfnAt\nkHTxhdw22Io3WQ2Msl7LtPal8MIGcAgn2hL0JV6kyRMboi1lyfxV5hYNtOhzJlYf\n3E+dxeD6C99aFOX4W/AYXj5WMZ5aWu5mp26HBjBuPUqn2G/WsbpWQQ==\n-----END RSA PRIVATE KEY-----\n",
  "admin_port": 8080,
  "api_cert": "-----BEGIN CERTIFICATE-----\nMIIC/zCCAeegAwIBAgIRAKo3XPDpUBDPAgh40ATRbg0wDQYJKoZIhvcNAQELBQAw\nEjEQMA4GA1UEChMHQWNtZSBDbzAgFw0xNzA3MDUxODIwNDJaGA8yMTE3MDYxMTE4\nMjA0MlowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBANGmp+qAT7JBKugTOIDRDTFmursO+qAtC2C3eZOsgaLpaEnrYwwN\npEnNhQEqH+2yokyylFsYOJEkb670/ea2WKcOebD9B3MAEwxOxmp8Nb4mnsHmu0YP\ngYp9nA/Q3VZhSbeNHDQCHB2qe9EV4SdOQIiNR/SQ7P7Ps+ODbchvCr6hzrSA1Pfw\nzfJAu917jJ7CnmaxjGW6+s9A4g4U2ZJomsIoMwG2jflgXOn+g5sx+ztqnYT72doU\nwPXmd8RxGGgyA5wvezUSg6GaAWWzoBV6xcot1euqEjQElkkCxTAz25UZ7LaUGnzo\nljji4mTyjhyFpq+9A3x1O5tXGBFoGO1x+/sCAwEAAaNOMEwwDgYDVR0PAQH/BAQD\nAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wFAYDVR0R\nBA0wC4IJbG9jYWxob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQA8Dbzj04N5bKeXhgq3\noHLDIkJBFsOi5s0CDRsR+yi7pMXnSseaKydqnYbtOEOSiVkLO6mlj4LZbqo6GpHG\nmO/N7YWfTHo6JHPsOgVv6JP/ebWA5KTFpTQ9rVPcgnN0xZCOGfvqu75egBkgaKed\nJ7gUawcCHGQXVUpUjyL6jXEsZPjmPrreeI2jZ4WntMnjiShOl4BExRe8SzTP4g6Q\nwOYTXhsHMAhTCAVSdQAJ+V7GiEWB0vF5n/QPsvF3HYhLaUwYsKDA8q89nP3fJOPd\n5a/I65WS3mILfPSEERWchdzMo+OZ8IxA5g+3LC13GjCc1XO/bi17RETkA9VVocG3\n6d5Q\n-----END CERTIFICATE-----\n",
  "api_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0aan6oBPskEq6BM4gNENMWa6uw76oC0LYLd5k6yBouloSetj\nDA2kSc2FASof7bKiTLKUWxg4kSRvrvT95rZYpw55sP0HcwATDE7Ganw1viaewea7\nRg+Bin2cD9DdVmFJt40cNAIcHap70RXhJ05AiI1H9JDs/s+z44NtyG8KvqHOtIDU\n9/DN8kC73XuMnsKeZrGMZbr6z0DiDhTZkmiawigzAbaN+WBc6f6DmzH7O2qdhPvZ\n2hTA9eZ3xHEYaDIDnC97NRKDoZoBZbOgFXrFyi3V66oSNASWSQLFMDPblRnstpQa\nfOiWOOLiZPKOHIWmr70DfHU7m1cYEWgY7XH7+wIDAQABAoIBAAWNrJUBoRrPrxtG\npxCCeR794aRi2TC1AMAnHAlVYHm4RRLwMUd4dQmfcA5/1yisuq/dayCem6D8nhi8\nVJ1v5xlFwON3UGMzdU22KHtZnvLSgxIP0pYggwXwHdotZi+LlDBQhJa8F5KRmYYI\nVlZ8NClp1KYd0KlPRyyXpqjQiDBUfKKPguD/jS+AMlO4fvqhaXIYmdtY51tyVv6U\nqFvwZ6xz7LI8tGp03fGhA102gQ9H1+A6uzPIMe7Hh5wVvMk/BmxK0cgunpuzEJ2Q\nvVXtcJ9H9LG/Mi2qgYUoqS442TdmUaRoy+oSQlqnAt5aWf0RsdC8P90RaPpcUZZv\nF/mr28ECgYEA9KFnTR9pRe97MC3+kqsyOPkVPDnQqxdJ2Nu6XxzSWSu8nFSHu31N\nPl1O45TQLgzkSNAcbBki2C0YchfNGS33OtpGc0hBJifPvcEc5Rtf9jMKBKsNep5n\nYKIeM+fuGEIK/HD7fFkY61KU3nu8XzthsDc+8jdTEWmZzfNwWlBIXp8CgYEA22UR\npnGI+pVxhAeNGCnGD/iEIsKDRtGrLHPhH4hZjrukC71+D/Q3obh9VyTHgy+SQKP4\n4Gf29xehbiMBERK8mkJRIW+1Ouv5/yBCis4LsDitQkE3vJ5ccd4EqjijC0BAVVNk\nqYOjXX5JqXYCOZUYVH1/KKuU4trWqUTMVFN0USUCgYBeNqsqMKbCoHC5JX2dzwEQ\noB1ljH6o5dczBazJZLg+T3HcY1HDC4bsNdNkIrPqiFyDDmNj3mplBzka97+tqt5E\ndDwduf4dS8feNLmEIv7aOt3o3lfamZcGyGkJZJF2FjlU785rHYVTXAKpjM4Hfz8o\nNp6vek8rrZfmkZL7tV+p0QKBgQCCdFmHZ/E0V1JVWIwcNxKvgm1HofOfU6L93rWZ\nI2FlTsvfs0BXSjceMW5ON+9uYQYM67Nb9FXUXTe/Ho9O0J5W92H4iMzxiUlw24TV\ntmka0sirIc57mIqNpp+Ne/nvAbh/RAQSC9VDDYnNev8dsDr0Wl8XFteEAO4tXlxF\nNA5xBQKBgQCry3bDZvsZ/71DKe+TVZTq8qH+jEJHzxsEsa+33YCfOSZukcljl7T5\nGi0GQMRHyHPV5cW6ccUsyYyHQUfz06KeiEogbVDWTdcWgef7TX6cT72/IikvofKW\nO6Hs5bcwIgWiLuAIXfnQe8dCYrbAUlC4KWYbSXB3xae/frD5uBxEXQ==\n-----END RSA PRIVATE KEY-----\n",
  "aws_access_key_id": "",
  "aws_secret_access_key": "",
  "azure_blob_account_key": "",
  "azure_blob_account_name": "",
  "azure_blob_container": "",
  "azure_blob_service_base_url": "core.windows.net",
  "azure_use_https": true,
  "bucket": "",
  "ca_certs": "",
  "cluster_listen_interface": "10.0.21.74",
  "cluster_listen_port": 8095,
  "config_client_password": "",
  "config_client_url": "",
  "config_client_username": "",
  "config_server_disabled": false,
  "config_server_election_timeout": 10000000000,
  "config_server_heartbeat_interval": 1000000000,
  "config_server_maintenance_interval": 3600000000000,
  "config_server_quota_backend_bytes": 8000000000,
  "data_cache_generations": 4,
  "data_cache_size": 100,
  "dev_add_expect_header": false,
  "dev_n_shards": 36,
  "dev_shard0_downloads": 64,
  "dev_storer_simulate_errors": 0,
  "email_notification_enabled": false,
  "email_notification_from_address": "notifications@storreduce.local",
  "email_notification_smtp_host": "localhost",
  "email_notification_smtp_password": "",
  "email_notification_smtp_port": 25,
  "email_notification_smtp_username": "",
  "email_notification_to_address": "",
  "embedded_license": "-----BEGIN STORREDUCE LICENSE-----\nZApBChlBV1NfTWFya2V0cGxhY2VfU1JfTUVESVVNEhZzdXBwb3J0QHN0b3JyZWR1\nY2UuY29tGgwKABIAGgAiACoAMgASABoAIPQDKAAwATgASABQAVgBYABoBXAAegM3\nMmiAAQBTfSA3PG7F2Y3hTI/IX3+Opmhb5gxMc3yflGKYmMWYyMSRyA8+zT5CfR3a\n+IALWiPglqtV9RWzZ9Dcla5G5wmhG6xIaksVqeYmvHxh/tglWLMN0aj8bpnEQfaB\nrOinDbmRV0DTYX3v3+HNrYm1+JwufQ+EDm3iqtsmEQzvCv1jzNN9jdYwe6N995L6\nB8dh1XuwGJGeJ80OCPCiktTNjWRxnr8dhMrbiFCdOEW/UnAzI9XOAgIx0sgAVQ5A\nqv8Scb8HK6u2qV2jwhOODKyzSM/0z/8+KKNUG8+GJNIboqxiKYpAS/nzb9pLBcwu\nPJh57tZj1+KxumdD4IZJHn/5CGZ2\n-----END STORREDUCE LICENSE-----\n\nLicense details:\n----------------\nLicensed To:              AWS_Marketplace_SR_MEDIUM\nEmail:                  support@storreduce.com\n\nValid From Date:            NONE\nValid Until Date:           NONE\nCapacity (TB):              500\nHigh Availability:          DISABLED\nRead Only Replica:          ENABLED\nCross Region Replication:   DISABLED\nNo Store Only:              DISABLED\nEmbedded:                   TRUE\nDisable S3 Credentials:     TRUE (credentials disabled)\nLicense Server:             DISABLED\nLicense Server Max Clients: 5\nLicense Server Issued:      FALSE (not to be issued through license server)\nLicense Server Issued TTL:  72h\nStorReduce Server Disabled: FALSE",
  "hostname": "",
  "http_port": 80,
  "https_port": 443,
  "kms_endpoint": "",
  "kms_master_key_id": "",
  "license": "",
  "license_server_disabled": false,
  "license_server_url": "",
  "log_hash_verify": true,
  "max_write_speed": 0,
  "mlog_sourcer_bucket_max_memory_bytes": 256000000,
  "mlog_sourcer_network_gap_wait_time": 30000000000,
  "mlog_sourcer_network_max_memory_bytes": 64000000,
  "n_authenticators": 4,
  "n_shard_replicas": 2,
  "n_simultaneous_uploads": 8,
  "predictor_cache_generations": 4,
  "predictor_cache_size": 1000,
  "pubsub_multicast_address": "",
  "pubsub_multicast_network_interface": "eth0",
  "pubsub_multicast_port": 0,
  "pubsub_transport_protocol": "TCP",
  "read_only": false,
  "redirect_browsers": true,
  "region": "us-west-2",
  "replication_targets": null,
  "restore_pending": false,
  "s3_endpoint": "",
  "s3_signing_version": -1,
  "serve_dashboard_on_s3_ports": true,
  "server_side_encryption": false,
  "snapshot_copiers": 2,
  "stats_server_address": "127.0.0.1:9090",
  "stats_server_enabled": false,
  "storage_class": "STANDARD",
  "storreduce_server_disabled": false,
  "use_200_for_s3_deletes": false,
  "use_backend": "AWS",
  "use_backend_sub_type": ""
}