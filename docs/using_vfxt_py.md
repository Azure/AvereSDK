# Using vfxt.py 

This section describes the syntax for using vfxt.py. It explains frequently used options when performing basic operations like creating or modifying Avere vFXT clusters. 

Additional options are explained in the [vfxt.py Command Syntax and Options](syntax.md) document and in the platform-specific sections for [Azure](azure_options.md), [AWS](aws_options.md), and [GCE](gce_options.md). 

## Basic Syntax 

The basic form for a vfxt.py command is this: 

    vfxt.py --cloud-type type <authentication> <environment options> --<action>

Each vfxt.py command (except for information queries like `--help`) must include:

* The cloud provider parameter – for example, `azure` for Azure, `aws` for Amazon, or `gce` for Google.
* Authentication credentials for accessing the cloud API. The syntax is different depending on the cloud provider and authentication method you are using; read the setup section for [Azure](azure_reference.md), [Amazon Web Services](aws_reference.md), or [Google Cloud Platform](gcp_reference.md) for details. 
* The environment options for the cloud network or project (depending on the cloud provider). 
* An action to perform – for example, `--create` to create a new vFXT cluster.

Note that similar commands have different names if they are restricted to one type of cloud provider. For example, the option to set an Amazon location is `region` and the option for setting a Google location is `zone`. This difference serves as a check that the correct cloud service was specified. 

Actions include things like creating or destroying a cluster, adding nodes, and stopping or starting the cluster. The command `vfxt.py --help` lists all options.

## Create a Cluster

Use the `--create` action to instantiate a new vFXT cluster. 

```bash
vfxt.py	--cloud-type type             \
	<authentication options>      \
	<environment options>         \
	--create                      \
	--cluster-name cluster_name   \
	--admin-password cluster_password    \
	--instance-type instance_type 
```

You must supply the following parameters for a create operation:

* `--cluster-name user_specified_name` - The name for the new cluster.
* `--admin-password cluster_password` - The password for administering the cluster settings. This password is used to manage the cluster (either by logging into the Avere Control Panel or through the XML-RPC command-line interface) and also is required to modify or destroy the cluster with vfxt.py.  
* `--instance-type` *type* - The type of cloud VM to use for each vFXT node. 
   Check the documentation from your cloud provider to learn about instance types on your platform, and refer to the Avere vFXT Installation Guide for your cloud provider to understand the minimum instance type that can be used to create a vFXT node. An instance type that meets the minimum requirements will give better cost management, but a more powerful instance type will give better performance - choose the supported instance type that best meets your needs. 

### Initial Configuration for the New Cluster 

Use these options with the create command to set up the basic parameters for your new cluster.  

* `--nodes` *number_of_nodes* - The number of vFXT nodes to create in the cluster. The minimum required number of nodes is 3 (this is also the default value). 

* Cache size options - There are two ways to set the cluster cache size; choose one. 

  * `-node-cache-size` *size_in_GB* - The size of the data cache for each node. 

    If you use this option, the system automatically sets the number of data disks per node and the disk size. If you prefer to set these values individually, use the `data-disk-count` and `data-disk-size` options instead of using `node-cache-size`. 

  * `--data-disk-count` *number_of_disks* and `--data-disk-size` *size_in_GB* -  

    These options let you specify the number of virtual data storage disks to create for each node (count) and the size of each disk (size). 

    > Note: Be careful not to exceed your storage quota or other limits, which can cause the create command to return an error. 

    Each node in the cluster will have the same number of data disks, and each disk will be the same size. 

* `--data-disk-type` *volume_type* - The kind of data volume to use as vFXT node disks. Values depend on the cloud provider type: 

  * For GCE, options are `pd-ssd`, or `local-ssd`  
  * For AWS EC2, options are `gp2` (the default), or `io1`
  * For Azure, this term is not used because only one storage type is supported: `premium LRS`

* `--cluster-proxy-uri` *cluster_proxy_URL* - Address of a proxy server to set for the cluster. (Avere does not require using a proxy server.) Use the format http://*username*:*password*@*proxy_IP address*:*port*/ The port value is optional.

  Example: `--cluster-proxy-uri http://admin1:myGo0dpw42@203.0.113.29:8080/ `

  It is better to specify an IP address instead of a hostname so that the proxy server will work even if DNS is not reachable. 

* `--cluster-range` *IP_range* - An IP address range, in CIDR notation, that the cluster will use for client-facing IP addresses and for cluster management.  

* `--vserver` *vserver_name* - The name to use for the cluster vserver. If not specified, the default name is "vserver".  The vfxt.py create command gives one vserver per cluster. If you want to add vservers, use the Avere Control Panel or the XML-RPC API after creating the cluster. (Read [Creating and Working with VServers](https://azure.github.io/Avere/legacy/ops_guide/4_7/html/settings_overview.html#creating-and-working-with-vservers) in the cluster Configuration Guide to learn more about vservers, junctions, and the global namespace.)

* `--core-filer` *core_filer_name* - The name to use for creating a new cloud core filer as part of the cluster creation. If not specified, the default name is the name of the cloud service type (aws, azure, or gce), or nfs if you specified an NFS core filer. 

* `--bucket` *existing_bucket_name* - Specify an empty bucket to use for the core filer instead of creating a new one. (In Azure, use `--averecontainer` *storage_acct*/*container_name* instead.)

### Additional Create Settings

This section describes additional options that can be useful when creating a new vFXT cluster. 

**Skip Cleanup**

If there is an error, vfxt.py rolls back what was done. In some situations, you might want to prevent this rollback - for example, during troubleshooting. The `--skip-cleanup` option leaves nodes, buckets, routes, roles, and other entities in the state they had when the error occurred. Anything created during the operation is not removed.

```bash

vfxt.py	--cloud-type type         \
	<authentication options>  \
	<environment options>     \
	<action>                  \
	--skip-cleanup           
```

**No Core Filer**

vfxt.py can skip the creation of a bucket and the associated cloud core filer configuration. Use this option if you want to create a vFXT cluster and configure its storage afterward by using the Avere Control Panel or the XML-RPC command-line cluster configuration API. 

> Note: If you use the `--nfs-mount` option, vfxt.py does not attempt to create a cloud core filer. 

```bash

vfxt.py	--cloud-type type           \
	<authentication options>    \
	<environment options>       \
	<action>                    \
	--no-corefiler
```

**NFS Core Filer**

vfxt.py can configure an NFS core filer at cluster creation time if you provide the NFS mount point in the host:/path format. Note that if you specify an NFS core filer, vfxt.py does not create a cloud core filer.  If your storage appliance type is one of the values in `--nfs-type` you can use that option here to set it. (If you don’t set the `--nfs-type` option it defaults to "other".)  

```bash
vfxt.py	--cloud-type type         \
	<authentication options>  \
	<environment options>     \
	<action>                  \
	--nfs-mount mount_point_host:/path   \  
  	--nfs-type {NetappNonClustered|NetappClustered|EmcIsilon}    
```

**Cache Disk Sizes**

Data disks for the vFXT cache sizes can be configured independently with `--data-disk-size` and `--data-disk-count` at cluster creation time. A convenience option, `--node-cache-size`, automatically sizes these based on the given cache size (in GB).

```bash
vfxt.py	--cloud-type type           \
	<authentication options>    \
	<environment options>       \
	--create                    \
	--node-cache-size cache_size_per_node_in_GB    
```

## Cluster Management Actions

This section gives detailed descriptions of commonly used cluster management commands. 

### Specifying Which Cluster To Modify

Note that you must identify the cluster nodes when configuring an existing cluster with vfxt.py. There are two main ways to identify the cluster instances, depending on whether the cluster is running (online) or stopped (offline).  

* For a running cluster, supply the same credentials you would use to manage a cluster from the Avere Control Panel: 

  * The cluster's management address (an IP address guaranteed to be held by one of the cluster nodes for administrative access). Use `--management-address` to supply the IP address. 
  * The cluster's administrative password (you set this when you create the cluster). Use `--admin-password` to supply the password.

  The vfxt.py script uses this information to query the cluster and identify instances for each cluster node. 

* For actions on a stopped cluster, you must specify the cloud instance identifiers for the cluster nodes. (When a cluster is offline, you cannot query it using the management address and password.) Use the option `--instances` to provide the instance identifiers of each cluster node. 

  You can find instance identifiers from your cloud administrative console. The format varies by cloud provider; some providers use unique strings and others use a URL-style format. 


### Add Nodes to a Cluster

The `--add-nodes` option extends the cluster. 

Use the `--nodes` option to specify how many nodes to add. The cluster must be online. 

```bash

vfxt.py	--cloud-type type                \
	<authentication options>         \
	<environment options>            \
	--add-nodes                      \
	--nodes number_of_nodes_to_add   \
	--management-address cluster_mgmt_IP_address   \
	--admin-password cluster_password              \
	[<node options>]
```

There is no restriction on the number of nodes to add, but testing has shown that adding nodes in small batches (one to three at a time) runs more quickly and is less likely to encounter trouble than adding larger batches of nodes at once. 

New nodes will be identical to the existing cluster nodes unless you include options to customize them. You can use the following node options (from the `--create` command) with the `--add-nodes` command: 
* `--data-disk-count` *number_of_disks* and `--data-disk-size` *size_in_GB* 
* `--data-disk-type` *volume_type* 
* `--instance-type` *type* 

Read [Initial Configuration for the New Cluster](#initial-configuration-for-the-new-cluster) for details about these options. 

To *remove* nodes from the cluster, use the Avere Control Panel. Read the [Cluster > FXT Nodes](https://azure.github.io/Avere/legacy/ops_guide/4_7/html/gui_fxt_nodes.html) settings page documentation in the Avere OS Configuration Guide.

### Destroy a Cluster

The `--destroy` option permanently removes a cluster. 

```bash

vfxt.py	--cloud-type type                 \
	<authentication options>          \
	<environment options>             \
	--destroy                         \
	--management-address cluster_mgmt_IP_address    \
	--admin-password cluster_password               \
	[--quick-destroy]

```

If the cluster is offline, you must provide the node instance identifiers since they cannot be discovered from the cluster configuration. You do not need to provide the management address and password for an offline cluster. See [Specifying Which Cluster To Modify](#specifying-which-cluster-to-modify) for more information on identifying your cluster node instances. 

> CAUTION: Using the `--quick-destroy` option can cause data loss. 

A normal destroy action includes writing any remaining changed data in the cluster cache to the backend core filer storage. If you want to abandon any unwritten cached data, you can use the `--quick-destroy` option, which destroys the cluster cache without attempting to write its data to the backend. 

### Stop a Cluster

The `--stop` option takes a cluster out of service. A stopped cluster does not serve client requests or update stored data. Stopping the cluster also stops its cloud virtual machines so that they do not incur usage charges; however, disk usage and storage charges can still accumulate. 

```bash

vfxt.py	--cloud-type type           \
	<authentication options>    \
	<environment options>       \
	--stop                      \
	--management-address cluster_mgmt_IP_address    \
	--admin-password cluster_password 

```

### Start a Cluster

Restart a stopped cluster with the option `--start`. 

The system cannot query a stopped cluster for the node list, so you must provide a list of instance identifiers for the cluster nodes. 

```bash

vfxt.py	--cloud-type type         \
	<authentication options>  \
	<environment options>     \
	--start                   \
	--instances instance1_ID instance2_ID instance3_ID   

```

Separate the instance identifiers with spaces. 

The format of the identifiers depends on the cloud vendor, because different cloud providers have written their APIs to use different keys for instance lookup. 

* AWS uses a numeric instance ID in the form i-xxxxxxxxxxxxxxxxx
* GCE and Azure use the instance name, which is the text string you used to name the cluster followed by the node numbers, -01, -02, etc.

### Proxy Configuration for API Commands  

There are two different proxy configuration options in vfxt.py:

* `--proxy-uri`, to send API commands through a proxy server
*  `--cluster-proxy-uri`, to set the vFXT cluster's proxy server. 

This section describes the `--proxy-uri` option, which affects API commands. 

To configure vfxt.py to issue cloud API calls through a proxy server, use the `--proxy-uri` setting. The proxy argument must be used on each command that you want to send over the proxy. 

```bash

vfxt.py	--cloud-type type            \
	<authentication options>     \
	<environment options>        \
	<action>                     \
	--proxy-uri API_proxy_URL

```

Specify the proxy server in this format:  http://*username*:*password*@*address*:*port_number*

You can use either an IP address or a hostname in the API proxy address value. (For the cluster proxy address, an IP address is preferred to avoid reliance on a domain name lookup service.)

### Proxy Configuration for the Cluster  

There are two different proxy configuration options in vfxt.py:
* `--proxy-uri` to send API commands through a proxy server
* `--cluster-proxy-uri` to set the vFXT cluster's proxy server 
This section describes the `--cluster-proxy-uri` option, which affects the configuration of the vFXT cluster. 

```bash

vfxt.py	--cloud-type type          \
	<authentication options>   \
	<environment options>      \
	<action>                   \
	--cluster-proxy-uri cluster_proxy_URL

```

Specify the proxy server in this format:  http://*username*:*password*@*IP_address*:*port_number* 

Example: `--cluster-proxy-uri http://vfxtcluster:goodpw@203.0.113.76:8080/` 

### Update Software

Use the `--upgrade` option to update the cluster’s Avere OS software. 

> Note: The cluster must have SSL access to the Avere software download site, https<!-- -->://download.averesystems.com, to obtain the new distribution. Make sure that cluster has outbound and inbound access to this URL. Typically, ports 443 and 22 must be open to allow this; refer to the appendix of the vFXT installation guide for your cloud provider to learn more about required ports and whitelisted URLs.  

The `--upgrade-url` element is required. Supply the URL for downloading the software image (for example, https<!-- -->://download.averesystems.com). Optionally, use `--upgrade-non-ha` to do the upgrade in parallel instead of one node at a time – note that this option has a higher impact on customer-facing latency than the standard upgrade does.  

```bash

vfxt.py	--cloud-type type          \
	<authentication options>   \
	<environment options>      \
        --upgrade                  \
        --upgrade-url software_download_url

```

## Interactive Mode

The vfxt.py script can be used in a Python interactive session by passing the `--interact` parameter. Interactive mode can be useful for API testing, or for validating authentication and environment options. The `--interact` option is a simple command-line switch that initializes a service object with the vfxt.py command-line options and allows you to inspect it or run code within an interactive session. 

```bash

vfxt.py	--cloud-type type          \
	<authentication options>   \
	<environment options>      \
	--interact 

```

An example session:

```bash

# ./vfxt.py --cloud-type gce --on-instance --interact

--- Service object available as 'service' ---

>>> service.export()
{'subnetwork_id': None, 'zone': ['us-central1-a'], 'network_id': 'gce1', 'access_token': u'ya29.Cj4ZAxwtZZZQP8MJ6Z6Pf_uZZZZZZiwARn291ekyz_igBntzZzPx4BchAbmsoJ84XpNiWRrp0cjy66HnsFZDw', 'client_email': 'projectid-compute@developer.gserviceaccount.com', 'project_id': 'some-project'}
>>> help(service)

```


## Next Step: Additional Command Options

Read [Command Syntax and Options](syntax.md) for more optional arguments.  
