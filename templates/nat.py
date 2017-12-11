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

import troposphere.elasticloadbalancing as elb
from troposphere.elasticloadbalancing import Policy as ELBPolicy

from troposphere.autoscaling import AutoScalingGroup, Tag
from troposphere.autoscaling import LaunchConfiguration

t = Template()

# Take an existing VPC and a subnet having access to an S3 endpoint

# Existing VPC input
VPCIDParam = t.add_parameter(Parameter(
    "VPCID",
    Description="The VPC ID you wish to deploy in",
    Type="AWS::EC2::VPC::Id",
))

# Subnet with S3 endpoint
SubnetsWithS3EndpointParam = t.add_parameter(Parameter(
    "SubnetsWithS3Endpoint",
    Description="The private subnets with a configured S3 endpoint. Recommended to be spread across multiple AZ's.",
    Type="List<AWS::EC2::Subnet::Id>",
))

# Key pair for autoscaling NAT instances
KeyPairNameParam = t.add_parameter(Parameter(
    "KeyPairName",
    Description="Name of an existing EC2 KeyPair to enable SSH access to the instances",
    Type="AWS::EC2::KeyPair::KeyName",
    ConstraintDescription="must be the name of an existing EC2 KeyPair."
))

DeployUserAccessKey = t.add_parameter(Parameter(
    "DeployUserAccessKey",
    Type="String",
    Description="The access key of the deploy user",
))

DeployUserSecretKey = t.add_parameter(Parameter(
    "DeployUserSecretKey",
    Type="String",
    Description="The secret key of the deploy user",
))

# Accept security group accepting port 80, 443 for autoscaling instances
AutoscalingSecurityGroupParam = t.add_parameter(Parameter(
    "AutoscalingSecurityGroupParam",
    Type="String",
    Description="Security group for NAT instances & LB. Recommended inbound open for TCP 80, 443",
))

DeployBucket = t.add_parameter(Parameter(
    "DeployBucket",
    Type="String",
    Description="The S3 bucket with the cloudformation scripts.",
))

NATInstanceTypeParam = t.add_parameter(Parameter(
    "NATInstanceType",
    Description="EC2 instance type for NAT autoscaling group",
    Type="String",
    Default="m4.large",
    ConstraintDescription="must be a valid EC2 instance type."
))

DesiredCapacityParam = t.add_parameter(Parameter(
    "DesiredCapacity",
    Description="Number of desired NAT instances",
    Type="Number",
    Default=1
))

MinSizeParam = t.add_parameter(Parameter(
    "MinSize",
    Description="Min number of NAT instances",
    Type="Number",
    Default=1
))

MaxSizeParam = t.add_parameter(Parameter(
    "MaxSize",
    Description="Max number of NAT instances",
    Type="Number",
    Default=1
))

# Mapping of AMIs - TODO
t.add_mapping('AWSAMIRegion', {
    "ap-northeast-1": {},
    "ap-northeast-2": {},
    "ap-south-1": {},
    "ap-southeast-1": {},
    "ap-southeast-2": {},
    "ca-central-1": {},
    "eu-central-1": {},
    "eu-west-1": {},
    "eu-west-2": {},
    "sa-east-1": {},
    "us-east-1": {},
    "us-east-2": {},
    "us-west-1": {},
    "us-west-2": { "NATAMI": "ami-7d07dd05" }
})

# Create an autoscaling group

LaunchConfig = t.add_resource(LaunchConfiguration(
    "LaunchConfiguration",
    Metadata=cloudformation.Metadata(
            cloudformation.Authentication({
            "DeployUserAuth": cloudformation.AuthenticationBlock(
                type="S3",
                accessKeyId=Ref(DeployUserAccessKey),
                secretKey=Ref(DeployUserSecretKey)
                )
            }),
            cloudformation.Init({
            "config": cloudformation.InitConfig(
                files=cloudformation.InitFiles({
                    "/home/ec2-user/script.sh": cloudformation.InitFile(
                        source=Join('', [
                            "http://",
                            Ref(DeployBucket),
                            ".s3.amazonaws.com/scripts/script.sh"
                        ]),
                        mode="000550",
                        owner="root",
                        group="root",
                        authentication="DeployUserAuth"),

                    "/usr/sbin/configure-storreduce-pat.sh": cloudformation.InitFile(
                        source=Join('', [
                            "http://",
                            Ref(DeployBucket),
                            ".s3.amazonaws.com/scripts/configure-storreduce-pat.sh"
                        ]),
                        mode="000550",
                        owner="root",
                        group="root",
                        authentication="DeployUserAuth"),
                }),
                commands={
                    "init": {
                        "command": Join("", [
                            "/home/ec2-user/script.sh && \
                             /usr/sbin/configure-storreduce-pat.sh"
                        ])
                    }
                }
            )
        }))
    
    ),
    UserData=Base64(Join('', [
        """
        #!/bin/bash -xe
        /opt/aws/bin/cfn-init -v """,
        "    --resource AutoscalingGroup",
        "    --stack ", Ref("AWS::StackName"),
        "    --region ", Ref("AWS::Region"), "\n",

        "cfn-signal -e $?",
        "    --resource AutoscalingGroup",
        "    --stack ", Ref("AWS::StackName"),
        "    --region ", Ref("AWS::Region"), "\n"
    ])),
    ImageId=FindInMap("AWSAMIRegion", Ref("AWS::Region"), "NATAMI"),
    KeyName=Ref(KeyPairNameParam),
    BlockDeviceMappings=[
        ec2.BlockDeviceMapping(
            DeviceName="/dev/sda1",
            Ebs=ec2.EBSBlockDevice(
                VolumeSize="8"
            )
        ),
    ],
    SecurityGroups=[Ref(AutoscalingSecurityGroupParam)],
    InstanceType=Ref(NATInstanceTypeParam),


    #IamInstanceProfile=Ref(EC2InstanceProfile),
    InstanceMonitoring="false",

    
))

LoadBalancer = t.add_resource(LoadBalancer(
    "LoadBalancer",
    ConnectionDrainingPolicy=elb.ConnectionDrainingPolicy(
        Enabled=True,
        Timeout=120,
    ),
    Subnets=Ref(SubnetsWithS3EndpointParam),
    HealthCheck=elb.HealthCheck(
        Target="TCP:80/",
        HealthyThreshold="6",
        UnhealthyThreshold="2",
        Interval="10",
        Timeout="5",
    ),
    Listeners=[
        elb.Listener(
            LoadBalancerPort="80",
            InstancePort="80",
            Protocol="TCP",
        ),
        elb.Listener(
            LoadBalancerPort="443",
            InstancePort="443",
            Protocol="TCP",
        ),
    ],
    CrossZone=True,
    SecurityGroups=[Ref(AutoscalingSecurityGroupParam)],
    LoadBalancerName="NAT-LoadBalancer",
    Scheme="internal",
    Policies=[ELBPolicy(
        PolicyName="EnableProxyProtocol",
        PolicyType="ProxyProtocolPolicyType",
        Attributes=[
                  {
                    "Name": "ProxyProtocol",
                    "Value": "true"
                  }
                ],
        InstancePorts=[
            {
            "Ref": "SquidPort"
            }
        ]
        )]
))

AutoscalingGroup = t.add_resource(AutoScalingGroup(
    "AutoscalingGroup",
    DesiredCapacity=Ref(DesiredCapacityParam),
    LaunchConfigurationName=Ref(LaunchConfig),
    MinSize=Ref(MinSizeParam),
    MaxSize=Ref(MaxSizeParam),
    VPCZoneIdentifier=Ref(SubnetsWithS3EndpointParam),
    LoadBalancerNames=[Ref(LoadBalancer)],
    # AvailabilityZones=[Ref(VPCAvailabilityZone1), Ref(VPCAvailabilityZone2)], # Not strictly required?
    HealthCheckType="ELB",
    HealthCheckGracePeriod="300",
    # UpdatePolicy=UpdatePolicy(
    #     AutoScalingReplacingUpdate=AutoScalingReplacingUpdate(
    #         WillReplace=True,
    #     ),
    #     AutoScalingRollingUpdate=AutoScalingRollingUpdate(
    #         PauseTime='PT5M',
    #         MinInstancesInService="1",
    #         MaxBatchSize='1',
    #         WaitOnResourceSignals=True
    #     )
    # )
))






Deploy an autoscaling group of Amazon NAT AMIs
With load balancer

Configure load balancer, auto scaling group with the right health triggers

Output: load balancer instance, DNS name & IP address

Manual process
Configure any subnets requiring NAT to point 0.0.0.0/0 to the instance created by above
