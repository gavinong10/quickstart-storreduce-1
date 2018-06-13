from troposphere import Base64, FindInMap, GetAtt
from troposphere import Parameter, Output, Ref, Template
from troposphere import Join, Split, cloudformation, Select
from troposphere import If, Equals, Or, And, Not, Condition, Tags
from troposphere import Output, Sub
from troposphere.policies import (CreationPolicy,
                                  ResourceSignal)
from troposphere.certificatemanager import Certificate, DomainValidationOption
from troposphere.s3 import Bucket
from troposphere.iam import Role, Policy, InstanceProfile

import sys

import troposphere.elasticloadbalancingv2 as elb

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
    Description="The password for the StorReduce admin root user. This password is used to configure the StorReduce admin web interface and admin account for Grafana on the StorReduce Monitor server. StorReduce Monitor access to Elasticsearch and Kibana are also secured using Basic Auth against the StorReduce user management system.",
    Type="String",
    NoEcho=True
))

ShardsNumParam = t.add_parameter(Parameter(
    "ShardsNum",
    Description="The number of shards to use for StorReduce. Set to 0 for automatic configuration (i.e. 8 * number of servers)",
    Type="Number",
    MinValue=0,
))

ReplicaShardsNumParam = t.add_parameter(Parameter(
    "ReplicaShardsNum",
    Description="The number of replica shards to use for the StorReduce cluster. Replicas create redundancy for higher resiliency but use extra CPU and disk space",
    Type="Number",
    MinValue=0,
))

VPCCIDRParam = t.add_parameter(Parameter(
    "VPCCIDR",
    Description="CIDR Block for the VPC",
    Type="String",
    Default="10.0.0.0/16",
    AllowedPattern="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))$",
    ConstraintDescription="CIDR block parameter must be in the form x.x.x.x/16-28"
))

StorReduceHostNameParam = t.add_parameter(Parameter(
    "StorReduceHostName",
    Description="The hostname to be used to address StorReduce. Objects stored on StorReduce will be addressed http://hostname/bucket/key or http://bucket.hostname/key. StorReduce settings will automatically be configured to add the AWS internal DNS values of the instances within the VPC and the AWS default public DNS name of the load balancer. This field can be populated as a comma-separated list of other DNS names corresponding to aliases for the load balancer, or else left blank",
    Type="String",
))

# InvokeSSLCertParam = t.add_parameter(Parameter(
#     "InvokeSSLCert",
#     Description="Enables SSL on the load balancer with your own specified SSL certificate. If 'No' is selected, then SSLCertificateId, DomainName and ValidationDomainName do not need to be specified and StorReduce's self-signed certificate for HTTPS will be used.",
#     Type="String",
#     AllowedValues=["Yes", "No"]
# ))

# SSLCertificateIdParam = t.add_parameter(Parameter(
#     "SSLCertificatewId",
#     Description="(Required if 'Invoke SSL Cert' is 'Yes' and Domain Name & Validation Domain Name are undefined) - The SSL Certificate ID to use for the load balancer",
#     Type="String",
# ))

# DomainNameParam = t.add_parameter(Parameter(
#     "DomainName",
#     Description="(Required if 'Invoke SSL Cert' is 'Yes' and SSL Certificate ID is undefined) - The Domain Name to be used to generate an SSL certificate (not required if SSLCertificateId exists)",
#     Type="String",
# ))

# ValidationDomainNameParam = t.add_parameter(Parameter(
#     "ValidationDomainName",
#     Description="(Required if 'Invoke SSL Cert' is 'Yes' and SSL Certificate ID is undefined) - The validation domain name to be used to validate domain ownership for an SSL certificate (not required if SSLCertificateId exists)",
#     Type="String",
# ))

RemoteAccessCIDRParam = t.add_parameter(Parameter(
    "RemoteAccessCIDR",
    AllowedPattern="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))$",
    ConstraintDescription="CIDR block parameter must be in the form x.x.x.x/x",
    Description="Allowed CIDR block for bastion, StorReduce Monitor and load balancer access",
    Type="String",
))

VpcIdParam = t.add_parameter(Parameter(
    "VpcId",
    ConstraintDescription="Your VPC-ID must be in the form vpc-xxxxxxxx where 'x' can be a number or a letter.",
    Description="VPC-ID of your existing Virtual Private Cloud (VPC) where you want to deploy a StorReduce cluster",
    Type="AWS::EC2::VPC::Id",
))

KeyPairNameParam = t.add_parameter(Parameter(
    "KeyPairName",
    Description="Name of an existing EC2 KeyPair to enable SSH access to the instances",
    Type="AWS::EC2::KeyPair::KeyName",
    ConstraintDescription="must be the name of an existing EC2 KeyPair."
))

InstanceTypeParam = t.add_parameter(Parameter(
    "InstanceType",
    Description="StorReduce EC2 instance type",
    Type="String",
    Default="i3.4xlarge",
    AllowedValues=[
        "i3.large",
        "i3.xlarge",
        "i3.2xlarge",
        "i3.4xlarge",
        "i3.8xlarge",
        "i3.16xlarge",
        "i2.xlarge",
        "i2.2xlarge",
        "i2.4xlarge",
        "c3.large",
        "c3.xlarge",
        "c3.2xlarge",
        "c3.4xlarge",
        "c3.8xlarge"
    ],
    ConstraintDescription="must be a valid EC2 instance type."
))

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
        "i3.16xlarge",
        "i2.xlarge",
        "i2.2xlarge",
        "i2.4xlarge",
        "c3.large",
        "c3.xlarge",
        "c3.2xlarge",
        "c3.4xlarge",
        "c3.8xlarge"
    ],
    ConstraintDescription="must be a valid EC2 instance type."
))

BucketNameParam = t.add_parameter(Parameter(
    "BucketName",
    Description="The bucket to which StorReduce will store data. This should be a unique name, not an existing bucket as a new bucket will be created",
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
    Description="A list of VPC public subnets to span for the StorReduce Load Balancer to cover",
    Type="List<AWS::EC2::Subnet::Id>"
))

PrivateSubnetsToSpanParam = t.add_parameter(Parameter(
    "PrivateSubnetsToSpan",
    Description="A list of VPC private subnets to span for StorReduce instances to reside. This number must equal the number of availability zones specified",
    Type="List<AWS::EC2::Subnet::Id>"
))

StorReduceLicenseParam = t.add_parameter(Parameter(
    "StorReduceLicense",
    Description="A StorReduce license",
    ConstraintDescription="must be a current and valid StorReduce license.",
    Type="String"
))

QSS3BucketNameParam = t.add_parameter(Parameter(
    "QSS3BucketName",
    Description="S3 bucket name for the Quick Start assets. Quick Start bucket name can include numbers, lowercase letters, uppercase letters, and hyphens (-). It cannot start or end with a hyphen (-)",
    ConstraintDescription="Quick Start bucket name can include numbers, lowercase letters, uppercase letters, and hyphens (-). It cannot start or end with a hyphen (-).",
    Default="aws-quickstart",
    Type="String",
    AllowedPattern="^[0-9a-zA-Z]+([0-9a-zA-Z\\-]*[0-9a-zA-Z])*$"
))
QSS3KeyPrefixParam = t.add_parameter(Parameter(
    "QSS3KeyPrefix",
    Description="S3 key prefix for the Quick Start assets. Quick Start key prefix can include numbers, lowercase letters, uppercase letters, hyphens (-), and forward slash (/)",
    ConstraintDescription="Quick Start key prefix can include numbers, lowercase letters, uppercase letters, hyphens (-), and forward slash (/).",
    Default="quickstart-storreduce/",
    Type="String",
    AllowedPattern="^[0-9a-zA-Z\\-/]*$",
))


t.add_metadata({
    "AWS::CloudFormation::Interface": {
            "ParameterGroups": [
                {
                    "Label": {
                        "default": "StorReduce Configuration"
                    },
                    "Parameters": [
                        "KeyPairName",
                        "StorReducePassword",
                        "ShardsNum",
                        "ReplicaShardsNum",
                        "InstanceType",
                        "MonitorInstanceType",
                        "BucketName",
                        "NumSRRHosts",
                        "StorReduceLicense",
                        # "InvokeSSLCert",
                        # "SSLCertificateId",
                        # "DomainName",
                        # "ValidationDomainName",                     
                    ]
                },
                {
                    "Label": {
                        "default": "VPC Network Configuration"
                    },
                    "Parameters": [
                        "NumberOfAZs",
                        "VpcId",
                        "VPCCIDR",
                        "RemoteAccessCIDR",
                        "PrivateSubnetsToSpan",
                        "PublicSubnetsToSpan",
                    ]
                },
                {
                    "Label": {
                        "default": "AWS Quick Start Configuration"
                    },
                    "Parameters": [
                        "QSS3BucketName",
                        "QSS3KeyPrefix"
                    ]
                }
            ],
            "ParameterLabels": {
                "PrivateSubnetsToSpan": {
                    "default": "VPC Private Subnets"
                },
                "PublicSubnetsToSpan": {
                    "default": "VPC Public Subnets"
                },
                "VpcId": {
                    "default": "VPC ID"
                },
                "StorReducePassword": {
                    "default": "StorReduce Password"
                },
                "ShardsNum": {
                    "default": "Number of Shards"
                },
                "ReplicaShardsNum": {
                    "default": "Number of Replica Shards"
                },
                "StorReduceLicense": {
                    "default": "StorReduce license"
                },
                # "InvokeSSLCert": {
                #     "default": "Invoke SSL Cert"
                # },
                # "SSLCertificateId": {
                #     "default": "SSL Certificate ID"
                # },
                # "DomainName": {
                #     "default": "Domain Name"
                # },
                # "ValidationDomainName": {
                #     "default": "Validation Domain Name"
                # },
                "NumSRRHosts": {
                    "default": "Number of StorReduce servers"
                },
                "BastionAMIOS": {
                    "default": "Bastion AMI Operating System"
                },
                "BastionInstanceType": {
                    "default": "Bastion Instance Type"
                },
                "KeyPairName": {
                    "default": "Key Pair Name"
                },
                "InstanceType": {
                    "default": "Instance Type"
                },
                "MonitorInstanceType": {
                    "default": "Monitor Instance Type"
                },
                "BucketName": {
                    "default": "Bucket Name"
                },
                "NumberOfAZs": {
                    "default": "Number of Availability Zones"
                },
                "NumBastionHosts": {
                    "default": "Number of Bastion Hosts"
                },
                "QSS3BucketName": {
                    "default": "Quick Start S3 Bucket Name"
                },
                "QSS3KeyPrefix": {
                    "default": "Quick Start S3 Key Prefix"
                },
                "RemoteAccessCIDR": {
                    "default": "External Allowed Access CIDR"
                },
                "VPCCIDR": {
                    "default": "VPC CIDR"
                }
            }
        }



})


t.add_mapping('AWSAMIRegion', {
    "ap-northeast-1": {"AMI": "ami-07583061", "MonitorAMI": "ami-203df15f" },
    "ap-northeast-2": {"AMI": "ami-f12c8f9f", "MonitorAMI": "ami-5d832933" },
    "ap-southeast-1": {"AMI": "ami-d4c88da8", "MonitorAMI": "ami-92ada9ee" },
    "ap-southeast-2": {"AMI": "ami-a35ca5c1", "MonitorAMI": "ami-00b76862" },
    "ap-south-1": {"AMI": "ami-9d84d4f2", "MonitorAMI": "ami-70ac841f" },
    "eu-west-1": {"AMI": "ami-fc4d2f85", "MonitorAMI": "ami-a3272ada" },
    "sa-east-1": {"AMI": "ami-472d622b", "MonitorAMI": "ami-a65f04ca" },
    "us-east-1": {"AMI": "ami-2084be5a", "MonitorAMI": "ami-d70640a8" },
    "us-west-1": {"AMI": "ami-57f3ff37", "MonitorAMI": "ami-c8fe1aab" },
    "us-west-2": {"AMI": "ami-aee2a6d6", "MonitorAMI": "ami-7e571406" },
    "eu-central-1": {"AMI": "ami-613ca70e", "MonitorAMI": "ami-a88cbc43" },
    "us-east-2": {"AMI": "ami-dd0431b8", "MonitorAMI": "ami-0e1e206b" },
    "eu-west-2": {"AMI": "ami-86d1cbe2", "MonitorAMI": "ami-c5bd53a2" },
    "ca-central-1": {"AMI": "ami-1dde5a79", "MonitorAMI": "ami-9678fbf2" },
    "eu-west-3": {"AMI": "ami-55b40228", "MonitorAMI": "ami-fa2b9a87" },
})

StorReduceWebSecurityGroup = t.add_resource(ec2.SecurityGroup(
            "StorReduceWebSecurityGroup",
            GroupDescription="Enables remote access to port 80 and 443 for the StorReduce load balancer",
            SecurityGroupIngress=[
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="80",
                    ToPort="80",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="443",
                    ToPort="443",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="8080",
                    ToPort="8080",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
            ],
            VpcId=Ref(VpcIdParam)
        ))

MonitorSecurityGroup = t.add_resource(ec2.SecurityGroup(
            "MonitorSecurityGroup",
            GroupDescription="Enables remote access to port 3000 and 5601 for StorReduce monitor",
            SecurityGroupIngress=[
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="3000",
                    ToPort="3000",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="5601",
                    ToPort="5601",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="9200",
                    ToPort="9200",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
            ],
            VpcId=Ref(VpcIdParam)
        ))

AllInternalAccessSecurityGroup = t.add_resource(ec2.SecurityGroup(
            "AllInternalAccessSecurityGroup",
            GroupDescription="Enables StorReduce and SSH ports TCP access from within the VPC",
            SecurityGroupIngress=[
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="22",
                    ToPort="22",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="80",
                    ToPort="80",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="443",
                    ToPort="443",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="8095",
                    ToPort="8099",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="2379",
                    ToPort="2380",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="8080",
                    ToPort="8080",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="5044",
                    ToPort="5044",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="9090",
                    ToPort="9090",
                    CidrIp=Ref(VPCCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="80",
                    ToPort="80",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="443",
                    ToPort="443",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
                ec2.SecurityGroupRule(
                    IpProtocol="tcp",
                    FromPort="8080",
                    ToPort="8080",
                    CidrIp=Ref(RemoteAccessCIDRParam),
                ),
            ],
            VpcId=Ref(VpcIdParam)
        ))

SrrBucket = t.add_resource(Bucket(
    "SrrBucket",
    BucketName=Ref(BucketNameParam),
    DeletionPolicy="Retain"
))

# Create a role for StorReduce
StorReduceHostRole = t.add_resource(Role(
    "StorReduceHostRole",
    DependsOn=SrrBucket.title,
    Path="/",
    Policies=[
        Policy(
            PolicyName="aws-quick-start-s3-policy",
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "s3:GetObject"
                        ],
                        "Resource": {
                            "Fn::Sub": [
                                "arn:${Partition}:s3:::${QSS3BucketName}/${QSS3KeyPrefix}*",
                                {
                                    "Partition": {
                                        "Fn::If": [
                                            "GovCloudCondition",
                                            "aws-us-gov",
                                            "aws"
                                        ]
                                    }
                                }
                            ]
                        },
                        "Effect": "Allow"
                    }
                ]
            }),
        Policy(
        PolicyName="srr-quick-start-s3-policy-bucket",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": [
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads"
                    ],
                    "Resource": {
                        "Fn::Join": [
                            "",
                            [
                                "arn:aws:s3:::",
                                {
                                    "Ref": "BucketName"
                                }
                            ]
                        ]
                    },
                    "Effect": "Allow"
                }
            ]
        }),
        Policy(
        PolicyName="srr-quick-start-s3-policy-objects",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                                {
                                    "Action": [
                                        "s3:PutObject",
                                        "s3:GetObject",
                                        "s3:DeleteObject",
                                        "s3:ListMultipartUploadParts",
                                        "s3:AbortMultipartUpload"
                                    ],
                                    "Resource": {
                                        "Fn::Join": [
                                            "",
                                            [
                                                "arn:aws:s3:::",
                                                {
                                                    "Ref": "BucketName"
                                                },
                                                "/*"
                                            ]
                                        ]
                                    },
                                    "Effect": "Allow"
                                }
                            ]
        }),
        Policy(
        PolicyName="elb-join-policy",
        PolicyDocument={
            "Version": "2012-10-17",
            "Statement": [
                                {
                                    "Action": [
                                        "elasticloadbalancing:Describe*",
                                        "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                                        "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                                        "autoscaling:Describe*",
                                        "autoscaling:EnterStandby",
                                        "autoscaling:ExitStandby",
                                        "autoscaling:UpdateAutoScalingGroup",
                                        "autoscaling:SuspendProcesses",
                                        "autoscaling:ResumeProcesses"
                                    ],
                                    "Resource": "*",
                                    "Effect": "Allow"
                                }
                            ]
        })
        ],
    AssumeRolePolicyDocument={"Version": "2012-10-17", "Statement": [
        {
            "Action": ["sts:AssumeRole"],
            "Effect": "Allow",
            "Principal": {
                "Service": [
                    "ec2.amazonaws.com",
                ]
            }
        }
    ]},
))

StorReduceHostProfile = t.add_resource(InstanceProfile(
    "StorReduceHostProfile",
    DependsOn=StorReduceHostRole.title,
    Roles=[Ref(StorReduceHostRole)],
    Path="/"
))

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

    # t.add_condition("SSLCertificateIdIsUndefined", Equals(Ref(SSLCertificateIdParam), ""))

    # t.add_condition("InvokeSSLCert", Equals(Ref(InvokeSSLCertParam), "Yes"))

    # t.add_condition("InvokeSSLCert&SSLCertificateIdIsUndefined", And(Condition("InvokeSSLCert"), Condition("SSLCertificateIdIsUndefined")))
        
create_conditions()

# gen_SSL_certificate_resource = t.add_resource(
#     Certificate(
#         'StorReduceSSLCertificate',
#         Condition="InvokeSSLCert&SSLCertificateIdIsUndefined",
#         DomainName=Ref(DomainNameParam),
#         DomainValidationOptions=[
#             DomainValidationOption(
#                 DomainName=Ref(DomainNameParam),
#                 ValidationDomain=Ref(ValidationDomainNameParam),
#             ),
#         ]
#     )
# )

NetworkLB = t.add_resource(elb.LoadBalancer(
        "NetworkLoadBalancer",
        Name="NetworkLoadBalancer",
        Scheme="internet-facing",
        Subnets=Ref(PublicSubnetsToSpanParam),
        Type='network',
         CreationPolicy=CreationPolicy(
           ResourceSignal=ResourceSignal(Timeout='PT15M')
        )
    ))

######### Monitor VM Pre-setup ###########

eth0 = t.add_resource(ec2.NetworkInterface(
    "Eth0",
    Description="eth0",
    DependsOn=AllInternalAccessSecurityGroup.title,
    GroupSet=[Ref(AllInternalAccessSecurityGroup), Ref(MonitorSecurityGroup)], #Split(",", Join(",", [Join(",", Ref(SecurityGroupIdsParam)), Ref(MonitorSecurityGroup), ])),
    # SourceDestCheck=True,
    SubnetId=Select("0", Ref(PublicSubnetsToSpanParam)),
    Tags=Tags(
        Name="Interface 0",
        Interface="eth0",
    ),
))

######### End Monitor VM Pre-setup #######
srr_targets_80 = []
srr_targets_443 = []
srr_targets_8080 = []

def generate_new_instance(counter):
    # Create base StorReduce instance
    instance = ec2.Instance(BASE_NAME + str(counter))
    instance.DependsOn=[SrrBucket.title, StorReduceHostProfile.title, AllInternalAccessSecurityGroup.title]
    instance.ImageId = FindInMap("AWSAMIRegion", Ref("AWS::Region"), "AMI")
    instance.IamInstanceProfile = Ref(StorReduceHostProfile)
    # instance.AvailabilityZone = Select("0", Ref(AvailabilityZonesParam))
    instance.InstanceType = Ref(InstanceTypeParam)
    instance.KeyName = Ref(KeyPairNameParam)
    #instance.SecurityGroupIds = Ref(SecurityGroupIdsParam)
    instance.SecurityGroupIds=[Ref(AllInternalAccessSecurityGroup), Ref(StorReduceWebSecurityGroup)]

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
                    roleName=Ref(StorReduceHostRole), #Ref(HostRoleParam),
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
                                "\'",Ref(ShardsNumParam), "\' ",
                                "\'",Ref(ReplicaShardsNumParam), "\' ",
                                "\"", Ref(StorReduceHostNameParam), "\" ",
                                "\"", GetAtt(NetworkLB, "DNSName"), "\" ", 
                                "\"", Ref("AWS::Region"), "\" ",
                                "\"", GetAtt("Eth0", "PrimaryPrivateIpAddress"), "\" ",
                                "\"", Ref(NumSRRHostsParam), "\""])
                    }
                }
            )
        }))

    instance.Tags = [
        {
            "Key": "Name",
            "Value": "StorReduce-QS-Base-Host"
        }
    ]

    instance.CreationPolicy=CreationPolicy(
            ResourceSignal=ResourceSignal(Timeout='PT15M')
            )

    return instance

base_instance = generate_new_instance(counter)
t.add_resource(base_instance)
instances.append(base_instance)
srr_targets_80.append(elb.TargetDescription(
            Id=Ref(base_instance),
            Port=80))
srr_targets_443.append(elb.TargetDescription(
        Id=Ref(base_instance),
        Port=443))
srr_targets_8080.append(elb.TargetDescription(
        Id=Ref(base_instance),
        Port=8080))

counter += 1

num_mandatory_instances = MIN_INSTANCES - 1

# Create monitor VM
# -> sudo storreduce-monitor --initial_cluster_discovery_token="eyJDbHVzdGVySWQiOiJCREFBQzM1NC1GQ0MzLTQzNTgtQjY2MC02RjYwRUQwNDc4OEYiLCJFdGNkQ2xpZW50VXJsIjoiaHR0cDovLzEwLjAuMTQuMTc0OjIzNzkiLCJFdGNkQ2xpZW50UGFzc3dvcmQiOiIiLCJFdGNkQ2xpZW50VXNlcm5hbWUiOiIiLCJFeHRlcm5hbEV0Y2RTZXJ2ZXIiOmZhbHNlfQ=="
monitor_instance = t.add_resource(ec2.Instance(
    "MonitorInstance",
    # Fix connect-srr.sh and init-srr.sh
    DependsOn = [base_instance.title, StorReduceHostProfile.title],
    KeyName=Ref(KeyPairNameParam),
    NetworkInterfaces=[
        ec2.NetworkInterfaceProperty(
            NetworkInterfaceId=Ref(eth0),
            DeviceIndex="0",
        ),
    ],
    InstanceType=Ref(MonitorInstanceTypeParam),
    ImageId=FindInMap("AWSAMIRegion", Ref("AWS::Region"), "MonitorAMI"),
    Tags=Tags(Name="StorReduce-QS-Monitor-Host",),
    IamInstanceProfile=Ref(StorReduceHostProfile)
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
                    roleName=Ref(StorReduceHostRole), #Ref(HostRoleParam),
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
                        group="root"),
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
    # instance.AvailabilityZone = Select(str(subnet_index), Ref(AvailabilityZonesParam))
    instance.Metadata=cloudformation.Metadata(
            cloudformation.Authentication({
                "S3AccessCreds": cloudformation.AuthenticationBlock(
                    type="S3",
                    roleName=Ref(StorReduceHostRole), #Ref(HostRoleParam),
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
                    "\"", Ref(ShardsNumParam), "\" ",
                    "\"", Ref(ReplicaShardsNumParam), "\" ", 
                    "\"", Ref("AWS::Region"), "\" ",
                    "\"", GetAtt("Eth0", "PrimaryPrivateIpAddress"), "\" ",
                    "\"", Ref(NumSRRHostsParam), "\""])
                }
            }
        )
    }))
    instance.Tags = [
        {
            "Key": "Name",
            "Value": "StorReduce-QS-Host"
        }
    ]

def add_conditional(instance, counter):
    instance.Condition=CONDITION_COUNTER_PREFIX + str(counter + 1)
    return instance

def wrap_conditional(item, counter):
    return If(CONDITION_COUNTER_PREFIX + str(counter + 1),
                                                item,
                                                Ref("AWS::NoValue"))

for i in range(num_mandatory_instances):
    instance = generate_new_instance(counter)
    configure_for_follower(instance, counter)
    t.add_resource(instance)
    instances.append(instance)
    srr_targets_80.append(elb.TargetDescription(
            Id=Ref(instance),
            Port=80))
    srr_targets_443.append(elb.TargetDescription(
            Id=Ref(instance),
            Port=443))
    srr_targets_8080.append(elb.TargetDescription(
            Id=Ref(instance),
            Port=8080))
    counter += 1

for i in range(MAX_INSTANCES - MIN_INSTANCES):
    instance = generate_new_instance(counter)
    configure_for_follower(instance, counter)
    add_conditional(instance, counter)
    t.add_resource(instance)
    instances.append(instance)

    srr_target_80 = wrap_conditional(elb.TargetDescription(
            Id=Ref(instance),
            Port=80), counter)
    srr_target_443 = wrap_conditional(elb.TargetDescription(
            Id=Ref(instance),
            Port=443), counter)
    srr_target_8080 = wrap_conditional(elb.TargetDescription(
            Id=Ref(instance),
            Port=8080), counter)

    srr_targets_80.append(srr_target_80)
    srr_targets_443.append(srr_target_443)
    srr_targets_8080.append(srr_target_8080)

    counter += 1

StorReduceNLBTargetsPort80 = t.add_resource(elb.TargetGroup(
        "StorReduceNLBTargetsPort80",
        Name="StorReduceNLBTargetsPort80",
        Port=80,
        Protocol="TCP",
        Targets=srr_targets_80,
        VpcId=Ref(VpcIdParam)
    ))

StorReduceNLBTargetsPort443 = t.add_resource(elb.TargetGroup(
        "StorReduceNLBTargetsPort443",
        Name="StorReduceNLBTargetsPort443",
        Port=443,
        Protocol="TCP",
        Targets=srr_targets_443,
        VpcId=Ref(VpcIdParam)
    ))

StorReduceNLBTargetsPort8080 = t.add_resource(elb.TargetGroup(
        "StorReduceNLBTargetsPort8080",
        Name="StorReduceNLBTargetsPort8080",
        Port=8080,
        Protocol="TCP",
        Targets=srr_targets_8080,
        VpcId=Ref(VpcIdParam)
    ))

StorReduceNLBTargetsPort3000 = t.add_resource(elb.TargetGroup(
        "StorReduceNLBTargetsPort3000",
        Name="StorReduceNLBTargetsPort3000",
        Port=3000,
        Protocol="TCP",
        Targets=[elb.TargetDescription(
                    Id=Ref(monitor_instance),
                    Port=3000)
                ],
        VpcId=Ref(VpcIdParam)
    ))

StorReduceNLBTargetsPort5601 = t.add_resource(elb.TargetGroup(
        "StorReduceNLBTargetsPort5601",
        Name="StorReduceNLBTargetsPort5601",
        Port=5601,
        Protocol="TCP",
        Targets=[elb.TargetDescription(
                    Id=Ref(monitor_instance),
                    Port=5601)
                ],
        VpcId=Ref(VpcIdParam)
    ))

StorReduceNLBTargetsPort9200 = t.add_resource(elb.TargetGroup(
        "StorReduceNLBTargetsPort9200",
        Name="StorReduceNLBTargetsPort9200",
        Port=9200,
        Protocol="TCP",
        Targets=[elb.TargetDescription(
                    Id=Ref(monitor_instance),
                    Port=9200)
                ],
        VpcId=Ref(VpcIdParam)
    ))

t.add_resource(elb.Listener(
        "StorReduceNLBPort80Listener",
        Port="80",
        Protocol="TCP",
        LoadBalancerArn=Ref(NetworkLB),
        DefaultActions=[elb.Action(
            Type="forward",
            TargetGroupArn=Ref(StorReduceNLBTargetsPort80)
        )]
    ))

t.add_resource(elb.Listener(
        "StorReduceNLBPort443Listener",
        Port="443",
        Protocol="TCP",
        LoadBalancerArn=Ref(NetworkLB),
        DefaultActions=[elb.Action(
            Type="forward",
            TargetGroupArn=Ref(StorReduceNLBTargetsPort443)
        )]
    ))

t.add_resource(elb.Listener(
        "StorReduceNLBPort8080Listener",
        Port="8080",
        Protocol="TCP",
        LoadBalancerArn=Ref(NetworkLB),
        DefaultActions=[elb.Action(
            Type="forward",
            TargetGroupArn=Ref(StorReduceNLBTargetsPort8080)
        )]
    ))

t.add_resource(elb.Listener(
        "StorReduceNLBPort3000Listener",
        Port="3000",
        Protocol="TCP",
        LoadBalancerArn=Ref(NetworkLB),
        DefaultActions=[elb.Action(
            Type="forward",
            TargetGroupArn=Ref(StorReduceNLBTargetsPort3000)
        )]
    ))

t.add_resource(elb.Listener(
        "StorReduceNLBPort5601Listener",
        Port="5601",
        Protocol="TCP",
        LoadBalancerArn=Ref(NetworkLB),
        DefaultActions=[elb.Action(
            Type="forward",
            TargetGroupArn=Ref(StorReduceNLBTargetsPort5601)
        )]
    ))

t.add_resource(elb.Listener(
        "StorReduceNLBPort9200Listener",
        Port="9200",
        Protocol="TCP",
        LoadBalancerArn=Ref(NetworkLB),
        DefaultActions=[elb.Action(
            Type="forward",
            TargetGroupArn=Ref(StorReduceNLBTargetsPort9200)
        )]
    ))

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
        "NetworkLoadBalancerID",
        Value=Ref(NetworkLB),
        Description="Network Load Balancer ID"
    )
)

outputs.append(
    Output(
        "NetworkLoadBalancerDNSName",
        Value=GetAtt(NetworkLB.title, "DNSName"),
        Description="Network Load Balancer DNS Name"
    )
)

outputs.append(
    Output(
        "StorReduceAdminUIAddress",
        Value=Join("", ["http://", GetAtt(NetworkLB.title, "DNSName"), ":8080"]),
        Description="Address for StorReduce Administration"
    )
)

outputs.append(
    Output(
        "StorReduceHTTPEndpoint",
        Value=Join("", ["http://", GetAtt(NetworkLB.title, "DNSName"), ":80"]),
        Description="StorReduce S3 Endpoint over HTTP"
    )
)

outputs.append(
    Output(
        "StorReduceHTTPSEndpoint",
        Value=Join("", ["http://", GetAtt(NetworkLB.title, "DNSName"), ":443"]),
        Description="StorReduce S3 Endpoint over HTTPS"
    )
)

outputs.append(
    Output(
        "StorReduceMonitorGrafanaDashboardAddress",
        Value=Join("", ["http://", GetAtt(NetworkLB.title, "DNSName"), ":3000"]),
        Description="Address for Grafana Dashboard on StorReduce Monitor"
    )
)

outputs.append(
    Output(
        "StorReduceMonitorKibanaDashboardAddress",
        Value=Join("", ["http://", GetAtt(NetworkLB.title, "DNSName"), ":5601"]),
        Description="Address for Kibana Dashboard on StorReduce Monitor"
    )
)

outputs.append(
    Output(
        "StorReduceMonitorElasticAddress",
        Value=Join("", ["http://", GetAtt(NetworkLB.title, "DNSName"), ":9200"]),
        Description="Address for Elasticsearch on StorReduce Monitor"
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