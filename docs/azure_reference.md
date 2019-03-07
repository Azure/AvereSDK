# Quick Reference – Using vfxt.py with Microsoft Azure 

This section gives an overview of how to configure a vfxt.py installation to be able to create Avere clusters in a Microsoft Azure environment.

> Note: A wizard for creating an Avere vFXT for Azure clusters is available in the Azure Marketplace. Read the [Avere vFXT for Azure documentation](https://docs.microsoft.com/en-us/azure/avere-vfxt/) for more complete information about the template-based deploy and additional preconfiguration required. The deployment wizard  automates most of these steps. 

Configuring the Azure environment to allow vfxt.py access includes the following steps: 
* Create a virtual network and subnet for the cluster
* Create or identify a Linux-style system to use for vfxt.py commands 
* Install Azure Python modules on the command system
* Before creating a cluster make sure you have configured the following infrastructure: 

  * Check your subscription’s resource quotas and request an increase if needed
  * Create a role for the cluster nodes. (You must specify the role name when creating the cluster, as described [below](#creating-the-avere-runtime-role-in-azure-active-directory).)
  * Set up a storage account for the cluster cache and, optionally, for cloud-based backend data storage

Note that many of these steps require ownership privileges for the subscription that will host the cluster.

## Choosing a vfxt.py Command Console

The system that you use to issue vfxt.py commands must be a Linux-style system that meets the installation prerequisites described in vfxt.py Software Requirements at the beginning of this document. It also must have secure access to the cluster instances – for example, an Azure VM that is located in the same resource group, network, and subnet where your cluster will reside.

If creating a cloud-based VM for vfxt.py commands, you can use any instance type that can run a Linux operating system for command-line access; it does not need much processing power or storage. You can choose a general purpose A0 or A1 VM with HDD type disks. The VM should be created from the same subscription that you will use to create the cluster.

## Install the Azure SDK for Python

On the system where you will run vfxt.py, install the [Microsoft Azure SDK for Python](<https://github.com/Azure/azure-sdk-for-python#microsoft-azure-sdk-for-python>). This is available as a single meta-package named azure in the Python package installer:

`pip install –-user azure`

**Note:** The Azure Marketplace includes preconfigured images that you can use to quickly create an Avere vFXT cluster for Azure, or to create a cluster controller for a customized deploy or for cluster maintenance. 

## Azure Authentication Options

When issuing a vfxt.py command on a Microsoft Azure system, you must include the appropriate parameters to authenticate the system running vfxt.py to your Azure subscription. There are three main approaches to authentication, depending on your command console’s location (in the cloud environment or remote) and your system’s infrastructure and guidelines.

### Cloud Instance 

If running vfxt.py on an instance on the same virtual network where you are creating the cluster, you can query the instance metadata and obtain an authentication token. 

There are two basic steps to set up this authentication option: 

1. Create an instance that has managed service identity enabled
2. Change the role for the instance’s service principal from contributor to owner

When creating the instance, turn on the Managed Service Identity optional feature (read more in the [Azure Managed Service Identity documentation](<https://docs.microsoft.com/en-us/azure/app-service/app-service-managed-service-identity>)). This option creates a service principal (SP) in Azure AD for the instance. However, the default role for these instances is Contributor, which is insufficient for creating and managing an Avere vFXT cluster, so you need to change it to have the role Owner. 

To assign an owner role to the service principal, follow these steps: 

1. Find the principal ID for your instance by using a command like the one below.

```
az vm show 
    --resource-group group 
    --name instance_name 
    --query 'identity.principalId'
    --output tsv
```

2. Assign the Owner role to this instance. 

```
az role assignment create 
    --assignee principal_id 
    --scope /subscriptions/id 
    --role Owner
```

Now authenticate:
`vfxt.py --cloud-type azure --on-instance`

### Remote Console 

For Azure-hosted virtual machines, you can use **az login --identity** to obtain a token that allows you to use the `from-environment` option to log in. 

**[ xxx does this /\ actually belong here? How do you make it work exactly? xxx ]**

For other remote systems, after connecting to the Azure environment with an SSL tunnel or by using a VPN or ExpressRoute, run the configuration step `az login` before using vfxt.py.

```
az login
az account set --subscription id
```

Then authenticate using the credentials from that login:
`vfxt.py --cloud-type azure --from-environment`

### Service Principal Authentication Option 

A more complicated authentication strategy exists that does not require managed service identities or az login. This option can be used either from within Azure or remotely. 

To use this option, you must create a service principal specifically for cluster creation and administration, then provide that SP’s credentials to authenticate. Read the Azure documentation about [creating service principals for access control](<https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli>). 

Assign the owner role to the SP – see the commands in [Cloud Instance](#cloud-instance), above, for hints. 

When using this method to authenticate the instance, the Azure subscription ID and AD tenant ID are also required.

```
vfxt.py --cloud-type azure 
    --subscription-id id_number 
    --tenant-id 'id_number' 
    --application-id 'ID_number' 
    --application-secret 'password'
```

## Azure Environment Options

Required environment options for each vfxt.py command in Azure include the resource group, location, network, and subnet. If you are using Blob storage as a backend cloud core filer, you must also specify the storage account.

```
vfxt.py --cloud-type azure 
        <authentication options>
        --resource-group group 
        --storage-account account 
        --location location 
        --azure-network network 
        --azure-subnet subnet
```

## Extra Azure Configuration Options

Refer to [Azure Options](syntax.md#azure-options) or `vfxt.py --help` for details. Extra configuration options for Azure cloud environments include:

* Security groups 
* Tagging
* Data disk and root disk caching 
* Boot diagnostics 
* Additional resource groups

## Azure Cluster Settings 

This table shows example values that can be used when creating an Avere vFXT cluster for Azure. Please work with your Technology Solutions or support representative to determine the best options.

|   | vfxt.py script option | Default value | Other value options |
| ---------- | ---------- | ------------------ | ---------- | 
| VM instance type | `--instance-type` | `Standard_E32s_v3` |  |
| Node cache size | `--node-cache-size` | `1024` | `4096`, `8192` |
| Number of nodes | `--nodes` | `3` | `6` |
| **Storage options:** |||| 
| Defer creating storage | `--no-corefiler` | Omit this option  | `--no-corefiler` |
| Specify storage resource group  | `--storage-resource-group` | Omit this option if storage is in the same resource group as the cluster  | *group_name* |
| Specify existing empty container  | `--azurecontainer` | Omit this option (a new container is created by default) | *storage_acct/container_name* |

## Creating the Avere Runtime Role in Azure Active Directory

Before creating a cluster you need to set up a role to assign privileges to the cluster nodes. Refer to the [vFXT Installation Guide for Microsoft Azure](http://aka.ms/averedocs) for more complete information. 

The Avere vFXT system uses role-based access control to give vFXT cluster nodes the privileges they need to operate. For example, each cluster node needs the ability to access other vFXT nodes, to manage network infrastructure, and to modify storage resources.  

Create a custom role for the cluster nodes and scope it to the subscription that you will use for the cluster.

Copy the lines in this example, substituting your subscription ID in the `AssignableScopes` statement. Save the role in a .json file (for example, averecluster.json). 
<!-- xxx remove routes lines at GA? xxx  -->

```
{
    "AssignableScopes": [ "/subscriptions/your-subscription-ID" ],
    "Name": "avere-cluster",
    "IsCustom": "true",
    "Description": "Avere cluster runtime role",
    "NotActions": [],
    "Actions": [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/virtualNetworks/subnets/read",
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/networkSecurityGroups/join/action",
        "Microsoft.Network/routeTables/read",
        "Microsoft.Network/routeTables/routes/*",
        "Microsoft.Resources/subscriptions/resourceGroups/read"
        "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
        "Microsoft.Storage/storageAccounts/blobServices/containers/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/write"
    ],
    "DataActions": [
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"
    ]
}
```

In the Azure CLI, run this command (as subscription owner) to create the role definition. 

`az role definition create --role-definition` *path_to_file*

Example: 
`az role definition create --role-definition averecluster.json`

When you issue the vfxt.py `--create` command, you must pass the role name (from the `Name` value in the .json file)in the `--avere-role` argument.

Example: 

```bash
vfxt.py --cloud-type azure  --from-environment \
--resource-group "group"  --location "location" \
--azure-network "network" --azure-subnet "subnet" \
--create \
--cluster-name "name" --admin-password "password" \
--instance-type "type" --node-cache-size "size" \
--azure-role avere-cluster  \
--storage-account "account_name"
```

If you exclude the role name in the create command, vfxt.py attempts to create a default role for the cluster (similar to the one in the example above); however, if the vfxt.py user does not have sufficient permissions to create the role, the cluster creation will fail. 
