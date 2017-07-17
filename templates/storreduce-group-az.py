from troposphere import Base64, FindInMap, GetAtt
from troposphere import Parameter, Output, Ref, Template
from troposphere import Join, cloudformation, Select
from troposphere import If, Equals, Or, And, Not, Condition
from troposphere import Output, Sub
import sys

import troposphere.elasticloadbalancing as elb

MAX_INSTANCES = 29
MIN_INSTANCES = 3

NUM_AZS = int(sys.argv[1])

instances = []

import troposphere.ec2 as ec2

CONDITION_COUNTER_PREFIX = "NumInstancesLessThanOrEqualTo"

t = Template()

SSLCertificateIdParam = t.add_parameter(Parameter(
    "SSLCertificateId",
    Description="The SSL Certificate ID to use for the load balancer",
    Type="String",
))

LoadBalancerSecurityGroupParam = t.add_parameter(Parameter(
    "LoadBalancerSecurityGroup",
    Description="The security group associated with the load balancer",
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
    Default="c3.large",
    AllowedValues=[
        "t1.micro",
                "t2.nano",
                "t2.micro",
                "t2.small",
                "t2.medium",
                "t2.large",
                "m1.small",
                "m1.medium",
                "m1.large",
                "m1.xlarge",
                "m2.xlarge",
                "m2.2xlarge",
                "m2.4xlarge",
                "m3.medium",
                "m3.large",
                "m3.xlarge",
                "m3.2xlarge",
                "m4.large",
                "m4.xlarge",
                "m4.2xlarge",
                "m4.4xlarge",
                "m4.10xlarge",
                "c1.medium",
                "c1.xlarge",
                "c3.large",
                "c3.xlarge",
                "c3.2xlarge",
                "c3.4xlarge",
                "c3.8xlarge",
                "c4.large",
                "c4.xlarge",
                "c4.2xlarge",
                "c4.4xlarge",
                "c4.8xlarge",
                "g2.2xlarge",
                "g2.8xlarge",
                "r3.large",
                "r3.xlarge",
                "r3.2xlarge",
                "r3.4xlarge",
                "r3.8xlarge",
                "i2.xlarge",
                "i2.2xlarge",
                "i2.4xlarge",
                "i2.8xlarge",
                "d2.xlarge",
                "d2.2xlarge",
                "d2.4xlarge",
                "d2.8xlarge",
                "hi1.4xlarge",
                "hs1.8xlarge",
                "cr1.8xlarge",
                "cc2.8xlarge",
                "cg1.4xlarge"
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
    MaxValue=MAX_INSTANCES
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
    AllowedPattern="^[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"
))
QSS3KeyPrefixParam = t.add_parameter(Parameter(
    "QSS3KeyPrefix",
    Description="S3 key prefix for the Quick Start assets. Quick Start key prefix can include numbers, lowercase letters, uppercase letters, hyphens (-), and forward slash (/).",
    ConstraintDescription="Quick Start key prefix can include numbers, lowercase letters, uppercase letters, hyphens (-), and forward slash (/).",
    Default="",
    Type="String",
    AllowedPattern="^[0-9a-zA-Z-/]*$",
))

t.add_mapping('AWSAMIRegion', {
    "us-west-2":      {"AMI": "ami-9b3f23e2"}
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
        
create_conditions()

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
                Protocol="TCP",
                InstanceProtocol="TCP",
                SSLCertificateId=Ref(SSLCertificateIdParam)
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
    " --resource " + instance.title + " --region ", Ref("AWS::Region")
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
                        "command": Join("", ["echo      echo test > /home/ec2-user/test.txt && /home/ec2-user/init-srr.sh \"", 
                                Ref(BucketNameParam), "\" \'", 
                                Ref(StorReduceLicenseParam), "\' ",
                                "\"", GetAtt(elasticLB, "DNSName"), "\" ",
                                "\"", Ref(elasticLB), "\" ",
                                "\"", Ref("AWS::Region"), "\" ",
                                " > output.txt 2>&1"])
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
    return instance

base_instance = generate_new_instance(counter)
t.add_resource(base_instance)
instances.append(base_instance)
counter += 1

num_mandatory_instances = MIN_INSTANCES - 1

# Build the instance such that we specify the correct subnet ID

def configure_for_follower(instance, counter):
    subnet_index = counter % NUM_AZS
    instance.DependsOn = base_instance.title
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
                    "command": Join("", ["echo test > /home/ec2-user/test.txt && /home/ec2-user/connect-srr.sh \"", GetAtt(base_instance, "PrivateDnsName"), "\" \"", 
                    Ref(base_instance), "\" ",
                    "\"", Ref(elasticLB), "\" ",
                    "\"", Ref("AWS::Region"), "\" ",
                    " > output.txt 2>&1"])
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
for i in range(MIN_INSTANCES):
    outputs.append(generate_private_DNS_output(i))
    outputs.append(generate_private_IP_output(i))

for i in range(MIN_INSTANCES, MAX_INSTANCES):
    outputs.append(add_conditional(generate_private_DNS_output(i), i))
    outputs.append(add_conditional(generate_private_IP_output(i), i))


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