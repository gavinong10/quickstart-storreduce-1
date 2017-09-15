# quickstart-storreduce
## StorReduce on the AWS Cloud


This Quick Start automatically deploys a secure and fault-tolerant StorReduce cluster on the AWS Cloud, into a configuration of your choice.

StorReduce is a specialized cloud deduplication solution for companies that use object storage like Amazon Simple Storage Service (Amazon S3) for large volumes of data. With StorReduce on AWS, you can use StorReduce features such as deduplication, copy-on-write (COW) cloning of data, inter-regional or inter-cloud deduplicated replication, and much more.

This Quick Start uses AWS CloudFormation templates to set up a StorReduce cluster of 3-31 servers across 2-4 Availability Zones. You can deploy StorReduce within a new or existing virtual private cloud (VPC) across multiple Availability Zones, with traffic distributed evenly across StorReduce’s endpoints through a load balancer. 

The deployment and configuration tasks are automated by AWS CloudFormation templates that you can customize during launch. You can also use the AWS CloudFormation templates as a starting point for your own implementation.

![Quick Start architecture for StorReduce on AWS](https://d0.awsstatic.com/partner-network/QuickStart/datasheets/storreduce-on-aws-architecture-diagram.png)

For architectural details, best practices, step-by-step instructions, and customization options, see the [deployment guide](https://s3.amazonaws.com/quickstart-reference/storreduce/latest/doc/storreduce-on-the-aws-cloud.pdf).

To post feedback, submit feature ideas, or report bugs, use the **Issues** section of this GitHub repo.
If you'd like to submit code for this Quick Start, please review the [AWS Quick Start Contributor's Kit](https://aws-quickstart.github.io/). 
