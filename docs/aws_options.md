# AWS Command Options

These options can be used only if the `--cloud-type` value is `aws`. 

## AWS Authentication Options 

| | |
| ---------- | ------------------ |
| `--access-key` *AWS_access_key *| AWS access key (required for off-instance authentication) |
| `--secret-key` *AWS_secret_key* | AWS secret key (required for off-instance authentication) |

For authentication from within a cloud console on the AWS instance, use the generic option `--on-instance` instead of these keys.  

## AWS Environment Options

| <img width=300/> | |
| ----------------------- | ------------------ |
| `--region` *AWS_region* | AWS region in which to create the cluster |
| `--subnet` *subnet_name* [...] | One or more subnet names, separated by spaces (for example, subnet-xxxx subnet-yyyy) |
| `--govcloud` | Set additional environment requirements for AWS GovCloud instances. This option sets the following default values: <br/> `--iam-host iam.us.gov.amazonaws.com` <br/> `--arn aws-us-gov` |

## Additional AWS-Specific Options

| <img width=600/> | |
| ---------- | ------------------ |
| `--arn` *ARN_string* | Override the default Amazon Resource Name  |
| `--aws-tag` *key*:*value* [...] | Key:value pairs to be added as tags. To add multiple tags, use the option multiple times (example: `--aws-tag dept:finance -aws-tag sec:124` ) |
| `--data-disk-iops` *IOPS_count* | Number of sustained IOPS (for volume type io1) |
| `--ephemeral` | Use EC2 ephemeral disks for cache (**Warning:** Ephemeral disks increase the risk of data loss.) |
| `--iam-role` *IAM_role* | IAM role to assign to the cluster |
| `--iam-host` *IAM_host* | IAM host |
| `--iam-role-principal-service` *service_name* | Specifies the domain name for the principal service IAM role (needed to use Avere vFXT with certain geographic locations outside North America) |
| `--no-disk-encryption` | Disable use of encryption with data disks |
| `--no-ebs-optimized`  | Disable use of EBS optimization |
| `--placement-group` *group_name* | Name of a placement group to use |
| `--profile` *profile_name* | User profile to use when connecting to EC2/VPC/IAM |
 `--security-group` *group_ID* | Security group ID for the cluster (for example, sg-xxxx). Separate multiple values with spaces |
| `--dedicated-tenancy`  | Locates all cluster instances on dedicated hardware (not shared with other AWS customers). Using this option increases costs. If resources or quota space is unavailable the cluster creation can fail.  |



## Additional AWS Information

Read [Quick Reference - Using vfxt.py with Amazon Web Services](aws_reference.md) for more AWS-specific information. 
