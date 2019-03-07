# Quick Reference - Using vfxt.py with Amazon Web Services 

This section gives an overview of how to configure a vfxt.py installation to be able to create Avere clusters in an AWS Elastic Compute Cloud (EC2) environment.

**Note:** Read the [vFXT Installation Guide for Amazon Web Services](<https://azure.github.io/Avere//#vfxt>) for detailed information about setting up an Amazon cloud computing environment to create vFXT clusters. 

Configuring the AWS environment to give vfxt.py the necessary access includes the following steps. Refer to the AWS vFXT Installation Guide for complete information about how to set up these prerequisites: 

* Ensure that your account has sufficient resources and request a quota increase if needed. (Note that quota increase requests might take a day or more to be fulfilled.)
* Send your AWS account number to Avere Systems to gain access to the vFXT image.
* Create a virtual private cloud (VPC) configured with a subnet.
* Establish an appropriate IAM policy for creating vFXT clusters.
* Associate the role with the vfxt.py user: 

   * If using a cloud instance local to your cloud environment to run vfxt.py, create the VM with the cluster management IAM role. 
   * If using a remote system to run vfxt.py, create a user with that role, and establish the user’s access key and secret key pair. When beginning a vfxt.py session from a remote console, pass the user keys to the cloud system to authenticate the system. 

* On the console where you will use vfxt.py to run commands, install the Python Boto library to allow Python to interact with the AWS API.

## Instance Requirements for running vfxt.py in AWS

If using a cloud-based VM to run the vfxt.py script, you can use any instance type that can run a Linux operating system for command-line access.

The instance must be created with the IAM role for cluster creation. Read [Create the Cluster Management Role](#create-the-cluster-management-role) for more information. 

## Install the AWS SDK for Python 

On the system where you will run vfxt.py, install the Python Boto library. 

    pip install -–upgrade --user boto

## Create the Cluster Management Role

In your AWS environment, you must create a role with a policy that allows the associated users to manipulate instances, storage, and roles, among other things. vfxt.py will connect to your private cloud as a user with this role. 

There are multiple steps. 

* First, you must create a policy that enables access. 
* Second, create a role that uses that policy. 
* Third, create a user that is associated with that role. 

These settings are made in the AWS Management Console. Read the AWS vFXT installation guide for the details of each step.  

Make sure the policy has settings like the following. 

```
{ 
    "Statement": [ 
        { 
            "Resource": "*",
            "Action": [ 
                "ec2:Describe*",
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "ec2:RebootInstances",
                "ec2:StartInstances",
                "ec2:StopInstances",
                "ec2:CreateTags",
                "ec2:DeleteTags",
                "ec2:ModifyInstanceAttribute",
                "ec2:CreateVolume",
                "ec2:DeleteVolume",
                "ec2:AttachVolume",
                "ec2:DetachVolume",
                "ec2:CreateSnapshot",
                "ec2:DeleteSnapshot",
                "ec2:RegisterImage",
                "ec2:DeregisterImage",
                "ec2:CreateImage",
                "ec2:DeleteRoute",
                "s3:CreateBucket",
                "s3:DeleteBucket",
                "s3:SetTag",
                "s3:ListBucket",
                "iam:AddRoleToInstanceProfile",
                "iam:CreateInstanceProfile",
                "iam:CreateRole",
                "iam:DeleteInstanceProfile",
                "iam:DeleteRole",
                "iam:DeleteRolePolicy",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:ListRolePolicies",
                "iam:GetInstanceProfile",
                "iam:PutRolePolicy",
                "iam:RemoveRoleFromInstanceProfile",
                "iam:PassRole"
            ],
            "Effect": "Allow"
        } 
    ],
    "Version": "2012-10-17"
} 
``` 

This example is the most general case; if your organization has defined more specific policy statements, you can use those instead, as long as the resulting permissions are similar. 

## Create a User with the Cluster Manager Role 

If you will use vfxt.py from a remote cluster (that is, from a machine outside the AWS VPC that hosts your cluster), you must create a user that has the ability to create clusters. When using vfxt.py, you must pass that user's credentials to AWS to authorize vfxt.py to create or modify vFXT clusters. 

This step is not required if using vfxt.py from an on-instance command line.

There are several ways to associate a user with a role or policy, and the best method for your situation depends on what other infrastructure you have set up in your AWS system. One method is to add the user to a group with the needed policy. Consult the [AWS IAM User Guide](<https://aws.amazon.com/documentation/iam/>) for details.

After creating the user and assigning appropriate permissions, copy out the user credentials to use to authorize with vfxt.py commands. In the IAM console, click the **Encryption Settings** button to create and manage user credentials. Create at least one access key ID and secret key value pair to use with vfxt.py commands.  

## AWS Authentication Options

When executing a vfxt.py command, you must provide the user credentials defined above to authenticate to the cloud environment. The process is slightly different if running in a local cloud console or if using a remote system. 

### Local Cloud Instance

To run vfxt.py on a VM in the same cloud environment where you will be creating clusters, use the AWS EC2 service to create a new instance. When creating the instance, you can use any type. Make sure to specify the IAM role created above before starting the instance. 

Detailed instructions for creating an instance with the cluster manager role are included in the [vFXT Installation Guide for Amazon Web Services](<https://azure.github.io/Avere//#vFXT>).

After creating the instance, you can pass authentication credentials from vfxt.py by querying the instance metadata to obtain an authentication token:

    vfxt.py --cloud-type aws --on-instance

### Remote Console

If using a remote system to run vfxt.py, you must pass user credentials for an authorized user to the cloud system where you are creating vFXT clusters. This user must be associated with the cluster manager role or policy, as described in [Create a User with the Cluster Manager Role](<#create-a-user-with-the-cluster-manager-role>), above. 

Use the key pair to authenticate as the user: 

    vfxt.py --cloud-type aws --access-key access_key --secret-key secret_key 

If you have configured the AWS command-line utility (awscli) with your credentials, you can use the `--from-environment` option to import them into vfxt.py:

    vfxt.py --cloud-type aws --from-environment

## AWS Environment Options
The region and subnet arguments provide enough information to query the VPC configuration. For cross-availability-zone (XAZ) configurations, you can provide multiple subnets - each in a different zone - separated by spaces.

```
vfxt.py --cloud-type aws 
        --access-key access_key
        --secret-key secret_key 
        --region AWS_region 
        --subnet subnet subnet2 subnet3 
```

### Configuring AWS GovCloud

The AWS GovCloud region has custom settings beyond the GovCloud specific region. The Amazon resource name (ARN) has a specific value for GovCloud resources (`aws-us-gov`), and the GovCloud IAM service has a custom endpoint name (`iam.us-gov.amazonaws.com`). 

Use the option `--govcloud` to set both of these automatically. 

```
vfxt.py --cloud-type aws                  \
        <authentication options>          \
        --region gov_cloud_region         \
        --subnet subnet subnet2 subnet3   \
        --govcloud
``` 

If you want to set them individually, use the following commands instead of the `--govcloud` option. 

* To set the GovCloud resource name: `--arn aws-us-gov` 
* To set the GovCloud endpoint name: `--iam-host iam.us-gov.amazonaws.com`

## Extra AWS Configuration Options

Refer to [AWS Command Options](aws_options.md#aws-command-options) or `vfxt.py --help` for details. Extra configuration options for AWS cloud environments include:

* Security groups 
* Placement group
* Tagging
* Disable encryption 
* Use ephemeral disks

## AWS Cluster Settings 

This table shows example values that can be used when creating a vFXT cluster on Amazon Web Services. Please work with your Technology Solutions or support representative to determine the best options.


|   | vfxt.py script option | Default value | Other value options |
| ---------- | ---------- | ------------------ | ---------- | 
| VM instance type | `--instance-type` | `r3.2xlarge` | `r3.8xlarge` |
| SSD type | `--data-disk-type` | `gp2` | `io1` |
| Node cache size | `--node-cache-size` | `1000` | Up to `8000` |
| Number of nodes | `--nodes` | `3` | Up to `20` |
| Bucket creation | `--no-corefiler` | Omit this option | `--no-corefiler` |


## AWS Tip - Using Additional Cloud Core Filers 

When you create a vFXT cluster with a cloud core filer, Avere software automatically creates an IAM policy that allows the cluster nodes to access the bucket for the core filer. (This is true regardless of whether you created a new bucket or if you specified an existing bucket to use as the core filer at creation time.)

The policy created allows access only to the specific storage bucket specified when creating the cluster. If you later want to add a different cloud core filer later, you must edit the IAM policy to let the nodes access the new bucket.

To allow access to a different bucket, you will change the resource statements in the IAM policy so that they allow access to any bucket, instead of restricting the cluster nodes to accessing one specific bucket.

(Optionally, you can add or substitute the new bucket name instead of opening access to all connected cloud buckets, but allowing access to all buckets is easier and more flexible. Refer to AWS documentation to learn how to add a second bucket resource.)

### Updating the Cluster IAM Policy

Follow these steps to revise the cluster policy to allow access to a different storage bucket. 

1. Open the AWS IAM console.

2. Identify the role created for the cluster. The role name has the form `policy_avere_cluster_role_`*##########_cluster_name*

3. Select the role for your cluster, then click the **Edit Policy** link at the bottom of the page. 

4. Find the resource lines that specify the original cloud core filer. They will have the form 

```
"Resource": [
               "arn:aws:s3:::bucket_name"
```

There usually are two resource statements, one like the one above, and one that includes `/*` after the bucket name. 

5. Replace the bucket names in these statements with a wildcard character to allow access to all buckets. Specifically: 

    * Change `arn:aws:s3:::`*bucket_name* to `arn:aws:s3:::*`  
    * Change `arn:aws:s3:::`*bucket_name*`/*` to `arn:aws:s3:::*/*`   

6. Click **Apply Policy** when done. 
