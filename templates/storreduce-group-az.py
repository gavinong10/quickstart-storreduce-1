from troposphere import Base64, FindInMap, GetAtt
from troposphere import Parameter, Output, Ref, Template
from troposphere import Join, Split, cloudformation, Select
from troposphere import If, Equals, Or, And, Not, Condition, Tags
from troposphere import Output, Sub
from troposphere.policies import (CreationPolicy,
                                  ResourceSignal)
from troposphere.certificatemanager import Certificate, DomainValidationOption

import sys

import troposphere.elasticloadbalancing as elb

# // Gavin TODO: Fix TaskCat

# Connect Monitor VM to cluster:
# -> sudo storreduce-monitor --initial_cluster_discovery_token="eyJDbHVzdGVySWQiOiJCREFBQzM1NC1GQ0MzLTQzNTgtQjY2MC02RjYwRUQwNDc4OEYiLCJFdGNkQ2xpZW50VXJsIjoiaHR0cDovLzEwLjAuMTQuMTc0OjIzNzkiLCJFdGNkQ2xpZW50UGFzc3dvcmQiOiIiLCJFdGNkQ2xpZW50VXNlcm5hbWUiOiIiLCJFeHRlcm5hbEV0Y2RTZXJ2ZXIiOmZhbHNlfQ=="

MAX_INSTANCES = 31
MIN_INSTANCES = 3

NUM_AZS = int(sys.argv[1])

instances = []

import troposphere.ec2 as ec2

CONDITION_COUNTER_PREFIX = "NumInstancesLessThanOrEqualTo"

t = Template()

StorReducePasswordParam = t.add_parameter(Parameter(
    "StorReducePassword",
    Description="Password for the StorReduce admin root user",
    Type="String",
    NoEcho=True
))

SSLCertificateIdParam = t.add_parameter(Parameter(
    "SSLCertificateId",
    Description="The SSL Certificate ID to use for the load balancer",
    Type="String",
))

DomainNameParam = t.add_parameter(Parameter(
    "DomainName",
    Description="The Domain Name to be used to generate an SSL certificate (not required if SSLCertificateId exists)",
    Type="String",
))

ValidationDomainNameParam = t.add_parameter(Parameter(
    "ValidationDomainName",
    Description="The validation domain name to be used to validate domain ownership for an SSL certificate (not required if SSLCertificateId exists)",
    Type="String",
))

LoadBalancerSecurityGroupParam = t.add_parameter(Parameter(
    "LoadBalancerSecurityGroup",
    Description="The security group associated with the load balancer",
    Type="AWS::EC2::SecurityGroup::Id"
))

# Gavin TODO:  Add both MonitorInstance and AllInternal to monitor VM
MonitorSecurityGroupParam = t.add_parameter(Parameter(
    "MonitorSecurityGroup",
    Description="The security group associated with the Monitor VM",
    Type="AWS::EC2::SecurityGroup::Id"
))

HostProfileParam = t.add_parameter(Parameter(
    "HostProfile",
    Description="The host profile to associate with the StorReduce instance(s)",
    Type="String"
))

HostRoleParam = t.add_parameter(Parameter(
    "HostRole",
    Description="The host role to associate with the StorReduce instance(s) for pulling scripts",
    Type="String"
))

KeyPairNameParam = t.add_parameter(Parameter(
    "KeyPairName",
    Description="Name of an existing EC2 KeyPair to enable SSH access to the instances",
    Type="AWS::EC2::KeyPair::KeyName",
    ConstraintDescription="must be the name of an existing EC2 KeyPair."
))

InstanceTypeParam = t.add_parameter(Parameter(
    "InstanceType",
    Description="EC2 instance type",
    Type="String",
    Default="i3.4xlarge",
    AllowedValues=[
        "i3.xlarge",
        "i3.2xlarge",
        "i3.4xlarge",
        "i3.8xlarge",
        "i3.16xlarge"
    ],
    ConstraintDescription="must be a valid EC2 instance type."
))

# Gavin TODO: Make Monitor Instsance Type Selectable from master
MonitorInstanceTypeParam = t.add_parameter(Parameter(
    "MonitorInstanceType",
    Description="EC2 instance type",
    Type="String",
    Default="i3.large",
    AllowedValues=[
        "i3.large",
        "i3.xlarge",
        "i3.2xlarge",
        "i3.4xlarge",
        "i3.8xlarge",
        "i3.16xlarge"
    ],
    ConstraintDescription="must be a valid EC2 instance type."
))

BucketNameParam = t.add_parameter(Parameter(
    "BucketName",
    Description="The bucket to which StorReduce will store data",
    Type="String",
    ConstraintDescription="must be a valid S3 bucket name.",
))

NumSRRHostsParam = t.add_parameter(Parameter(
    "NumSRRHosts",
    Description="The number of StorReduce hosts to configure",
    Type="Number",
    MinValue=MIN_INSTANCES,
    MaxValue=MAX_INSTANCES,
    AllowedValues=[i for i in range(MIN_INSTANCES, MAX_INSTANCES + 1) if i % 2],
    ConstraintDescription="Number of StorReduce hosts must be an odd number between 3 and 31."
))

PublicSubnetsToSpanParam = t.add_parameter(Parameter(
    "PublicSubnetsToSpan",
    Description="The VPC public subnets to span",
    Type="List<AWS::EC2::Subnet::Id>"
))

PrivateSubnetsToSpanParam = t.add_parameter(Parameter(
    "PrivateSubnetsToSpan",
    Description="The VPC private subnets to span",
    Type="List<AWS::EC2::Subnet::Id>"
))

AvailabilityZonesParam = t.add_parameter(Parameter(
    "AvailabilityZones",
    Description="The availability zone in which to place the EC2 instance",
    Type="List<AWS::EC2::AvailabilityZone::Name>"
))

SecurityGroupIdsParam = t.add_parameter(Parameter(
    "SecurityGroupIds",
    Description="The securitys group associated with the instance",
    Type="List<AWS::EC2::SecurityGroup::Id>"
))

StorReduceLicenseParam = t.add_parameter(Parameter(
    "StorReduceLicense",
    Description="A StorReduce license",
    ConstraintDescription="must be a current and valid StorReduce license.",
    Type="String"
))

QSS3BucketNameParam = t.add_parameter(Parameter(
    "QSS3BucketName",
    Description="S3 bucket name for the Quick Start assets. Quick Start bucket name can include numbers, lowercase letters, uppercase letters, and hyphens (-). It cannot start or end with a hyphen (-).",
    ConstraintDescription="Quick Start bucket name can include numbers, lowercase letters, uppercase letters, and hyphens (-). It cannot start or end with a hyphen (-).",
    Default="gong-cf-templates",
    Type="String",
    AllowedPattern="^[0-9a-zA-Z]+([0-9a-zA-Z\\-]*[0-9a-zA-Z])*$"
))
QSS3KeyPrefixParam = t.add_parameter(Parameter(
    "QSS3KeyPrefix",
    Description="S3 key prefix for the Quick Start assets. Quick Start key prefix can include numbers, lowercase letters, uppercase letters, hyphens (-), and forward slash (/).",
    ConstraintDescription="Quick Start key prefix can include numbers, lowercase letters, uppercase letters, hyphens (-), and forward slash (/).",
    Default="",
    Type="String",
    AllowedPattern="^[0-9a-zA-Z\\-/]*$",
))

t.add_mapping('AWSAMIRegion', {
    "us-west-2":      {"AMI": "ami-b88a6cc0",
                       "MonitorAMI": "ami-b6886ece" }
})
  
BASE_NAME = "StorReduceInstance"
counter = 0

def create_conditions():
    condition_counter = 4
    base_condition = Equals(Ref(NumSRRHostsParam), 4)
    t.add_condition(CONDITION_COUNTER_PREFIX + str(condition_counter), base_condition)

    last_condition = CONDITION_COUNTER_PREFIX + str(condition_counter)
    for i in range(condition_counter + 1, MAX_INSTANCES + 1):
        t.add_condition(CONDITION_COUNTER_PREFIX + str(i), Or(Equals(Ref(NumSRRHostsParam), i), Condition(last_condition)))
        last_condition = CONDITION_COUNTER_PREFIX + str(i)

    t.add_condition("GovCloudCondition", Equals(Ref("AWS::Region"), "us-gov-west-1"))

    t.add_condition("SSLCertificateIdIsUndefined", Equals(Ref(SSLCertificateIdParam), ""))
        
create_conditions()


# TODO: Test - IF SSLCertificateID is empty

gen_SSL_certificate_resource = t.add_resource(
    Certificate(
        'StorReduceSSLCertificate',
        Condition="SSLCertificateIdIsUndefined",
        DomainName=Ref(DomainNameParam),
        DomainValidationOptions=[
            DomainValidationOption(
                DomainName=Ref(DomainNameParam),
                ValidationDomain=Ref(ValidationDomainNameParam),
            ),
        ]
    )
)

elasticLB = t.add_resource(elb.LoadBalancer(
        'ElasticLoadBalancer',
        Subnets=Ref(PublicSubnetsToSpanParam),
        CrossZone=True,
        # Instances=[Ref(instances[i]) for i in range(MIN_INSTANCES)] + [If(CONDITION_COUNTER_PREFIX + str(i + 1), Ref(instances[i]), Ref("AWS::NoValue")) for i in range(MIN_INSTANCES, MAX_INSTANCES)],
        # DependsOn=[instances[i].title for i in range(MIN_INSTANCES)] + [If(CONDITION_COUNTER_PREFIX + str(i + 1), instances[i].title, Ref("AWS::NoValue")) for i in range(MIN_INSTANCES, MAX_INSTANCES)],
        Listeners=[
            elb.Listener(
                LoadBalancerPort="80",
                InstancePort="80",
                Protocol="TCP",
                InstanceProtocol="TCP"
            ),
            elb.Listener(
                LoadBalancerPort="443",
                InstancePort="443",
                Protocol="SSL",
                InstanceProtocol="SSL",
                SSLCertificateId=If("SSLCertificateIdIsUndefined",Ref(gen_SSL_certificate_resource),Ref(SSLCertificateIdParam))
            ),
        ],
        HealthCheck=elb.HealthCheck(
            Target="HTTP:80/health_check",
            HealthyThreshold="3",
            UnhealthyThreshold="5",
            Interval="30",
            Timeout="5",
        ),
        SecurityGroups=[Ref(LoadBalancerSecurityGroupParam)]
    ))

######### Monitor VM Pre-setup ###########
eip1 = t.add_resource(ec2.EIP(
    "EIPMonitor",
    Domain="vpc",
))

eth0 = t.add_resource(ec2.NetworkInterface(
    "Eth0",
    Description="eth0",
    GroupSet=Split(",", Join(",", [Join(",", Ref(SecurityGroupIdsParam)), Ref(MonitorSecurityGroupParam), ])),
    # SourceDestCheck=True,
    SubnetId=Select("0", Ref(PublicSubnetsToSpanParam)),
    Tags=Tags(
        Name="Interface 0",
        Interface="eth0",
    ),
))

eipassoc1 = t.add_resource(ec2.EIPAssociation(
    "EIPAssoc1",
    NetworkInterfaceId=Ref(eth0),
    AllocationId=GetAtt("EIPMonitor", "AllocationId"),
    PrivateIpAddress=GetAtt("Eth0", "PrimaryPrivateIpAddress"),
))

######### End Monitor VM Pre-setup #######

def generate_new_instance(counter):
    # Create base StorReduce instance
    instance = ec2.Instance(BASE_NAME + str(counter))
    instance.DependsOn=elasticLB.title
    instance.ImageId = FindInMap("AWSAMIRegion", Ref("AWS::Region"), "AMI")
    instance.IamInstanceProfile = Ref(HostProfileParam)
    instance.AvailabilityZone = Select("0", Ref(AvailabilityZonesParam))
    instance.InstanceType = Ref(InstanceTypeParam)
    instance.KeyName = Ref(KeyPairNameParam)
    instance.SecurityGroupIds = Ref(SecurityGroupIdsParam)

    instance.SubnetId = Select("0", Ref(PrivateSubnetsToSpanParam))
    instance.UserData = Base64(Join("", [
    """
    #!/bin/bash -xe
    /opt/aws/bin/cfn-init -v --stack """, Ref("AWS::StackName"),
    " --resource " + instance.title + " --region ", Ref("AWS::Region"), 
    "\n",
    "/opt/aws/bin/cfn-signal -e $? --stack ", Ref("AWS::StackName"),
        "    --resource " + instance.title + " --region ", Ref("AWS::Region")
    ]))

    instance.Metadata= cloudformation.Metadata(
            cloudformation.Authentication({
                "S3AccessCreds": cloudformation.AuthenticationBlock(
                    type="S3",
                    roleName=Ref(HostRoleParam),
                    buckets=[Ref(QSS3BucketNameParam)]
                )
                
            }),
            cloudformation.Init({
            "config": cloudformation.InitConfig(
                files=cloudformation.InitFiles({
                    "/home/ec2-user/init-srr.sh": cloudformation.InitFile(
                        source=Sub(
                            "https://${" + QSS3BucketNameParam.title + "}.${QSS3Region}.amazonaws.com/${" + QSS3KeyPrefixParam.title + "}scripts/init-srr.sh",
                            **{"QSS3Region":If("GovCloudCondition",
                                                "s3-us-gov-west-1",
                                                "s3")}
                        ),
                        mode="000550",
                        owner="root",
                        group="root")
                }),
                commands={
                    "init-srr": {
                        "command": Join("", ["/home/ec2-user/init-srr.sh \"", 
                                Ref(BucketNameParam), "\" \'", 
                                Ref(StorReduceLicenseParam), "\' ",
                                "\'",Ref(StorReducePasswordParam), "\' ",
                                "\"", GetAtt(elasticLB, "DNSName"), "\" ",
                                "\"", Ref(elasticLB), "\" ",
                                "\"", Ref("AWS::Region"), "\" ",
                                "\"", GetAtt("Eth0", "PrimaryPrivateIpAddress"), "\""])
                    }
                }
            )
        }))

    instance.Tags = [
        {
            "Key": "Name",
            "Value": "SrrBaseHost"
        }
    ]

    instance.CreationPolicy=CreationPolicy(
            ResourceSignal=ResourceSignal(Timeout='PT15M')
            )
    return instance

base_instance = generate_new_instance(counter)
t.add_resource(base_instance)
instances.append(base_instance)
counter += 1

num_mandatory_instances = MIN_INSTANCES - 1

# Create monitor VM
# -> sudo storreduce-monitor --initial_cluster_discovery_token="eyJDbHVzdGVySWQiOiJCREFBQzM1NC1GQ0MzLTQzNTgtQjY2MC02RjYwRUQwNDc4OEYiLCJFdGNkQ2xpZW50VXJsIjoiaHR0cDovLzEwLjAuMTQuMTc0OjIzNzkiLCJFdGNkQ2xpZW50UGFzc3dvcmQiOiIiLCJFdGNkQ2xpZW50VXNlcm5hbWUiOiIiLCJFeHRlcm5hbEV0Y2RTZXJ2ZXIiOmZhbHNlfQ=="
monitor_instance = t.add_resource(ec2.Instance(
    "MonitorInstance",
    # Gavin TODO: Depend on the base instance of StorReduce and make 2nd instance depend on monitor
    # Fix connect-srr.sh and init-srr.sh
    DependsOn = base_instance.title,
    KeyName=Ref(KeyPairNameParam),
    NetworkInterfaces=[
        ec2.NetworkInterfaceProperty(
            NetworkInterfaceId=Ref(eth0),
            DeviceIndex="0",
        ),
    ],
    InstanceType=Ref(MonitorInstanceTypeParam),
    ImageId=FindInMap("AWSAMIRegion", Ref("AWS::Region"), "MonitorAMI"),
    Tags=Tags(Name="SRRMonitorVM",),
    IamInstanceProfile=Ref(HostProfileParam)
))

monitor_instance.UserData = Base64(Join("", [
    """
    #!/bin/bash -xe
    /opt/aws/bin/cfn-init -v --stack """, Ref("AWS::StackName"),
    " --resource " + monitor_instance.title + " --region ", Ref("AWS::Region"), 
    "\n",
    "/opt/aws/bin/cfn-signal -e $? --stack ", Ref("AWS::StackName"),
        "    --resource " + monitor_instance.title + " --region ", Ref("AWS::Region")
]))

monitor_instance.Metadata= cloudformation.Metadata(
            cloudformation.Authentication({
                "S3AccessCreds": cloudformation.AuthenticationBlock(
                    type="S3",
                    roleName=Ref(HostRoleParam),
                    buckets=[Ref(QSS3BucketNameParam)]
                )
                
            }),
            cloudformation.Init({
            "config": cloudformation.InitConfig(
                files=cloudformation.InitFiles({
                    "/home/ec2-user/monitor-srr.sh": cloudformation.InitFile(
                        source=Sub(
                            "https://${" + QSS3BucketNameParam.title + "}.${QSS3Region}.amazonaws.com/${" + QSS3KeyPrefixParam.title + "}scripts/monitor-srr.sh",
                            **{"QSS3Region":If("GovCloudCondition",
                                                "s3-us-gov-west-1",
                                                "s3")}
                        ),
                        mode="000550",
                        owner="root",
                        group="root")
                }),
                commands={
                    "monitor-srr": {
                        "command": Join("", ["/home/ec2-user/monitor-srr.sh \"", 
                                GetAtt(base_instance, "PrivateDnsName"), "\" \'", 
                                Ref(StorReducePasswordParam), "\'"])
                    }
                }
            )
        }))

monitor_instance.CreationPolicy=CreationPolicy(
            ResourceSignal=ResourceSignal(Timeout='PT15M')
            )

# Build the instance such that we specify the correct subnet ID

def configure_for_follower(instance, counter):
    subnet_index = counter % NUM_AZS
    if counter == 2:
        instance.DependsOn = "MonitorInstance"
    else:
        instance.DependsOn = BASE_NAME + str(counter - 1) #base_instance.title
    instance.SubnetId = Select(str(subnet_index), Ref(PrivateSubnetsToSpanParam))
    instance.AvailabilityZone = Select(str(subnet_index), Ref(AvailabilityZonesParam))
    instance.Metadata=cloudformation.Metadata(
            cloudformation.Authentication({
                "S3AccessCreds": cloudformation.AuthenticationBlock(
                    type="S3",
                    roleName=Ref(HostRoleParam),
                    buckets=[Ref(QSS3BucketNameParam)]
                )
                
            }),
            cloudformation.Init({
        "config": cloudformation.InitConfig(
            files=cloudformation.InitFiles({
                "/home/ec2-user/connect-srr.sh": cloudformation.InitFile(
                    source=Sub(
                        "https://${" + QSS3BucketNameParam.title + "}.${QSS3Region}.amazonaws.com/${" + QSS3KeyPrefixParam.title + "}scripts/connect-srr.sh",
                            **{"QSS3Region":If("GovCloudCondition",
                                            "s3-us-gov-west-1",
                                            "s3")}
                            
                    ),
                    mode="000550",
                    owner="root",
                    group="root")
            }),
            commands={
                "connect-srr": {
                    "command": Join("", ["/home/ec2-user/connect-srr.sh \"", GetAtt(base_instance, "PrivateDnsName"), "\" \'", 
                    Ref(StorReducePasswordParam), "\' ",
                    "\"", Ref(elasticLB), "\" ",
                    "\"", Ref("AWS::Region"), "\" ",
                    "\"", GetAtt("Eth0", "PrimaryPrivateIpAddress"), "\""])
                }
            }
        )
    }))
    instance.Tags = [
        {
            "Key": "Name",
            "Value": "SrrHost"
        }
    ]

def add_conditional(instance, counter):
    instance.Condition=CONDITION_COUNTER_PREFIX + str(counter + 1)
    return instance

for i in range(num_mandatory_instances):
    instance = generate_new_instance(counter)
    configure_for_follower(instance, counter)
    t.add_resource(instance)
    instances.append(instance)
    counter += 1

for i in range(MAX_INSTANCES - MIN_INSTANCES):
    instance = generate_new_instance(counter)
    configure_for_follower(instance, counter)
    add_conditional(instance, counter)
    t.add_resource(instance)
    instances.append(instance)
    counter += 1

def generate_private_DNS_output(counter):
    return Output(
        BASE_NAME+str(counter)+"PrivateDNS",
        Value=GetAtt(BASE_NAME+str(counter), "PrivateDnsName"),
        Description=BASE_NAME+str(counter)+" Private DNS"
    )

def generate_private_IP_output(counter):
    return Output(
        BASE_NAME+str(counter)+"PrivateIp",
        Value=GetAtt(BASE_NAME+str(counter), "PrivateIp"),
        Description=BASE_NAME+str(counter)+" Private IP"
    )

outputs = []
outputs.append(
    Output(
        "ElasticLoadBalancerID",
        Value=Ref(elasticLB),
        Description="ElasticLoadBalancerID" + " ID"
    )
)
# for i in range(MIN_INSTANCES):
#     outputs.append(generate_private_DNS_output(i))
#     outputs.append(generate_private_IP_output(i))

# for i in range(MIN_INSTANCES, MAX_INSTANCES):
#     outputs.append(add_conditional(generate_private_DNS_output(i), i))
#     outputs.append(add_conditional(generate_private_IP_output(i), i))


t.add_output(outputs)


print(t.to_json())


# "Vault2RecoveryAlarm": {
#             "Type": "AWS::CloudWatch::Alarm",
#             "Properties": {
#                 "AlarmDescription": "EC2 Autorecovery for Vault2 node. Autorecover if we fail EC2 status checks for 5 minutes.",
#                 "Namespace": "AWS/EC2",
#                 "MetricName": "StatusCheckFailed_System",
#                 "Statistic": "Minimum",
#                 "Period": "60",
#                 "EvaluationPeriods": "5",
#                 "ComparisonOperator": "GreaterThanThreshold",
#                 "Threshold": "0",
#                 "AlarmActions": [
#                     {
#                         "Ref": "VaultSNSTopic"
#                     },
#                     {
#                         "Fn::Join": [
#                             "",
#                             [
#                                 "arn:aws:automate:",
#                                 {
#                                     "Ref": "AWS::Region"
#                                 },
#                                 ":ec2:recover"
#                             ]
#                         ]
#                     }
#                 ],
#                 "Dimensions": [
#                     {
#                         "Name": "InstanceId",
#                         "Value": {
#                             "Ref": "Vault2"
#                         }
#                     }
#                 ]
#             }
#         }