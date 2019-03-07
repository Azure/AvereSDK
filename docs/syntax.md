
# vfxt.py Command Syntax and Options 

This section gives brief descriptions of vfxt.py command syntax. 

Note that options might have changed since this document was created in September 2018. Use the command `vfxt.py --help` to see accurate options for your version of the script.

## Required Parameters 

For all operations (except the help and version commands), these elements are required:

* `--cloud-type` {`aws`|`azure`|`gce`} - The cloud provider being used
* Authentication information (varies by provider)
* Environment information (varies by provider)
* Action (create, destroy, stop, start, add nodes)

For operations on existing vFXT clusters, you must supply information to identify the cluster instances. 

* For an online cluster, use `--management-address` and `--admin-password` to identify the cluster being modified and authorize changes.
* For an offline cluster, use `--instances` to supply the instance identifier for each node in the cluster. 

## Script Information Options

These options do not require any other parameters. 

| | | 
| ---------- | ------------------ |
| `-h`, `--help` | Show a help message and exit |
| `-v`, `--version` | Show the program's version number and exit |

## Script Behavior Options

These arguments affect how vfxt.py behaves.

| <img width=1500 /> | | 
| ---------- | ------------------ |
| `-d`, `--debug` | Give verbose feedback |
| `--interact` | Use Python interactive mode |
| `--proxy-uri` *URL* | Send vfxt.py calls through this proxy server. Include the username, password, and port - for example, `http://user:password@172.16.16.20:8080/` |
| `--skip-check` | Do not check quotas during a `--create` action |
| `--skip-cleanup`  | Do not remove resources (buckets, volumes, instances) created as part of the action when a failure occurs |
| `--wait-for-state` {`red`\|`yellow`\| `green`}  | After issuing the command, wait until the cluster has reached a particular state when validating success of the action. By default, vfxt.py waits until the cluster has only non-critical alerts (yellow status, based on the alert conventions used in the Avere Control Panel dashboard). The waiting system shows a status message like `INFO - Waiting for cluster healthcheck.` You should use this option only when troubleshooting a problem under the guidance of support staff.  |
| `--wait-for-state-duration` *time* | The amount of time (in seconds) to wait for the state specified in  `--wait-for-state`, above. If the time expires and the cluster is not in the required state, the cluster deployment fails. This option is ignored if used without the `--wait-for-state` option. |
| `--log` *log_file* | Automatically log output to the specified file |

## Cluster Actions

These options make up the basic actions for cluster creation and maintenance.

| <img width=450 /> | |
| ---------- | ------------------ |
| `--check` | Test API authentication credentials and check the account quota. Issues warnings if any required resources are at more than 80% utilization. |
| `--create`  | Create a new cluster. Read [Create a Cluster](using_vfxt_py.md#create-a-cluster) for details. |
| `--destroy` | Permanently remove a cluster. Read [Destroy a Cluster](using_vfxt_py.md#destroy-a-cluster) for details. |
| `--stop` | Take a cluster offline. Read [Stop a Cluster](using_vfxt_py.md#stop-a-cluster) for details. |
| `--start`  | Reactivate an offline cluster. Read [Start a Cluster](using_vfxt_py.md#start-a-cluster) for details. |
| `--add-nodes` | Add nodes to a cluster. Read [Add Nodes to a Cluster](using_vxt_py.md#add-nodes-to-a-cluster) for details. |
| `--upgrade` | Updates the Avere OS software for the cluster. Used with `--upgrade-url` and `--upgrade-non-ha` (described below). Read [Update Software](using_vfxt_py.md#update-software) for more information. |
| `--telemetry` | Starts a support data upload. You must accept privacy terms from the Avere Control Panel in order to use this option. Read [Using the Avere Control Panel Support Tab](<https://azure.github.io/Avere/legacy/ops_guide/4_7/html/support_overview.html>) for details. |
| `--telemetry-mode` *mode* | **XXX ??? XXX** |

### Cluster Action Modifiers

These options are used with the commands above.

| <img width=400 /> | |
| ---------- | ------------------ |
 `--quick-destroy` | When used with `--destroy`, this option skips flushing changed data from the cluster cache. **CAUTION: Using this option can cause data loss.** |
 `--upgrade-url` *URL* | Specifies the URL for downloading the software update. This value is required when using `--upgrade`. |
 `--upgrade-non-ha` | Upgrades vFXT nodes in parallel instead of one at a time. **Note:** This option disrupts access to the cluster. Client requests will be ignored during some phases of the software update process.  |

## Cluster Configuration Options

These options apply to any supported cloud provider.


### Authentication and Environment Options

| <img width=1500 /> | |
| ---------- | ------------------ |
| `--on-instance`        | Query the cloud environment for instance credentials. Use this option when running vfxt.py in a cloud instance instead of passing authentication credentials. Read the setup information for your cloud platform to learn more. |
| `--from-environment` | Query the local host configuration for service credentials. Use this option when running vfxt.py from a non-cloud host where you have installed your cloud provider's custom command-line tool (that is, Azure [az](<https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest>), Google [gcloud](<https://cloud.google.com/sdk/gcloud/>), or Amazon [aws](<https://aws.amazon.com/cli/>)) and configured it with the appropriate credentials. Read the CLI setup information for your cloud platform (linked in the tool names above) to learn more. |
| `--admin-password` *cluster_password* | Administrator password for cluster management. This option serves two functions: <br/> • When creating a cluster, this option sets the password for the admin login account. <br/> • When modifying an online cluster, use this option to supply the password in order to authenticate to the cluster. <br/> **Note:** You cannot use this option as a command to change an existing password. Use the Avere Control Panel web interface or the XML-RPC command-line API to change a cluster’s administrator password. |
| `--management-address` *cluster_mgmt_IP* | The cluster's management address. <br/>• When creating a cluster, this option sets the management IP address. <br/> • When modifying an online cluster, use this option to specify which cluster is being modified. |
| `--instances` *instance1_ID* *instance2_ID* *instance3_ID*  | Instance identifiers for the cluster nodes - use this to specify an offline cluster. Read [Specifying Which Cluster To Modify](using_vfxt_py.md#specifying-which-cluster-to-modify) for more information. |
`--s3-access-key` *S3_access_key* <br/> `--s3-secret-key` *S3_secret_key* <br/> `--s3-profile` *S3_profile* | Use these options if you need to pass an additional S3 credential for your cluster resources. |
| `--ssh-key` *key*  | SSH key for cluster authentication - this option allows for systems that use key-based authentication via SSH instead of password-based authentication. <br/> For Amazon Web Services, provide the SSH key name; for Azure and Google Compute, provide the path to the public key file. |

### Miscellaneous Cluster Options

| <img width=1000 /> | |
| ---------- | ------------------ |
| `--cluster-name` *cluster_name* | Name for the cluster (also used to tag resources). This name should be compatible with DNS, since some cloud providers process it into a DNS hostname. |
| `--cluster-range` *IP_range* | IP address range (CIDR format) for the cluster. This range is assigned to the cluster to use for client traffic and cluster management tasks.  |
| `--cluster-proxy-uri` *URL* | Proxy resource for the cluster - for example, `http://user:pass@172.16.16.20:8080/`. **Note:** Use the IP address rather than hostname in case DNS becomes unreachable. |
| `--junction` *vserver_junction_path* | Sets the GNS path for the vserver's junction. The path must start with `/`. If not set, the default value is the cloud provider name (`/gce` , `/azure`, or `/aws`), or the last segment of the NFS export path (/smithj for an NFS export with the path /files/smithj)  |
| `--labels` *key*:*value*  | Specify a key:value pair label for the cluster. Specify one label at a time; you can use as many label statements as needed. |
| `--no-vserver` | Skips automatically creating a vserver with the cluster |
| `--root-size` *boot_disk_size_in_GB* | Use this to specify the size of each node's boot disk, in GB. <br/> **Note:** This setting might not be honored by some cloud providers. |
| `--timezone` *zone* | Cluster time zone (in TZ database format - for example, `--timezone America/Puerto_Rico`) |
| `--trace-level` *level* | Trace level for the created cluster |
| `--vserver` *vserver_name* | Name for the vserver that will be created with the cluster |

### Node and Node Cache Options

| <img width=1200 /> | |
| ---------- | ------------------ |
| `--nodes` *number_of_nodes*     | Number of nodes to create or add to the cluster. |
| `--node-cache-size` *size_in_GB* | Size of the data cache space for each node (in GB). Use this to automatically set `--data-disk-count` and `--data-disk-size`, or use those two settings to set each manually. All nodes will have identical storage capacity. Read [Initial Configuration for the New Cluster](using_vfxt_py.md#initial-configuration-for-the-new-cluster) for additional information. |
| `--data-disk-count` *number_of_disks* | Number of data disk volumes per cluster node. This option can be used with `--create` or with `--add-nodes`. <br/>You can use `--node-cache-size` to set this automatically. Read [Initial Configuration for the New Cluster](using_vfxt_py.md#initial-configuration-for-the-new-cluster) for additional information.  |
|`--data-disk-size` *size_in_GB* | Size of data disk volumes to create for the vFXT cluster. This option can be used with `--create` or with `--add-nodes`. <br/>You can use `--node-cache-size` to set this automatically. Read [Initial Configuration for the New Cluster](using_vfxt_py.md#initial-configuration-for-the-new-cluster) for additional information.     |
| `--data-disk-type` *volume_type* | Type of storage volumes to create for the vFXT cluster cache. Values depend on the cloud provider; AWS values are `gp2` (default), `io1`, or `standard`. GCE values are `pd-ssd` (default), or `local-ssd`. Azure supports only one disk type (premium LRS) and does not use this option. |
|`--instance-type` *instance_type* | Type of instance to use when creating nodes. This is required for creating a cluster or when adding nodes to a cluster. Read [Create a Cluster](using_vfxt_py.md#create-a-cluster) for details. |
| `--image-id` *image_ID_or_URI* | Optionally, use this parameter to specify an image instead of using the default image when creating the cluster. Consult support for guidance before using this advanced option. <br/>The image ID or URL should match what your cloud provider uses. <br/> • AWS image ID example: ami-ff6e9c9f <br/> • GCE image URL example: https<!-- -->://ww<!-- -->w.googleapis.<!-- -->com/compute/v1/projects/tribal-parsec-845/global/images/avere-vfxt-4625 <br/> • Azure URN example: microsoft-avere:vfxt-preview:avere-vfxt-node:latest |
| `--skip-load-defaults` | Do not look for the defaults.json file in standard online locations. You must specify the installation version manually with the `--image-id` parameter | 
| `--join-instance-address` | Join nodes using the instance address rather than the management address |
| `--join-wait wait_time` | Set a custom time (in seconds) to wait for nodes to join the cluster. This is a troubleshooting option that should only be used when recommended by support staff. |

### Core Filer Options

| <img width=800 /> | |
| ---------- | ------------------ |
| `--core-filer` *core_filer_name* | Name for the core filer that will be created with the cluster. |
| `--bucket` *s3_bucket_name* <br/> or <br/> `--azurecontainer` *blob_container_name* | Name of an existing, empty cloud storage container to use as the core filer. <br/> • For AWS or GCE, use `--bucket` to specify an S3 bucket <br/> • For Azure, use `--azurecontainer` to specify a blob container |
| `--no-corefiler`  | Skip creating a cloud core filer when creating the cluster. This will create a cluster without any core filers. |
| `--nfs-mount` host:/path | NFS mountpoint to use as the core filer (in host:/path format). If you use this option when creating a cluster, it will use the specified resource instead of creating a cloud core filer. |
| `--nfs-type` {`NetappNonClustered`\| `NetappClustered`\|`EmcIsilon`} | Specify the type of appliance used as the core filer in the `--nfs-mount` argument. This type is important for correct SMB operation and cannot be easily detected. |
| `--subdir` *path_under_mountpoint* | Use this option with `--nfs-mount` to mount a subdirectory on the NFS storage system. |
| **XXX review below XXX** |  |
| `--core-filer-key-file` *filepath* | Specify the path to store the encryption key for a newly created core filer. This parameter is required when cloud core filer encryption is enabled. |
| `--core-filer-encryption-password` *password* | Password to use for core filer encryption. If this parameter is not set, the cluster administrator password is used. | 
| `--bucket-not-empty` | Use the specified storage endpoint, which has existing Avere-formatted data **XXX is this right? XXX** |
| `--disable-bucket-encryption` | Don't allow encryption for objects written to the storage endpoint | 
| `--disable-bucket-compression` | Don't allow compression for objects written to the storage endpoint |
| `--disable-bucket-https` | Don't use HTTPS for communication with the storage endpoint |
| `--disable-bucket-https-verify` | Don't verify encryption certificates for communication with the storage endpoint |


## Provider-specific Options

Read the linked articles to learn about vfxt.py arguments that apply only to specific cloud providers: 

* [Azure-specific command options](azure_options.md)
* [AWS-specific command options](aws_options.md)
* [GCE-specific command options](gce_options.md)
