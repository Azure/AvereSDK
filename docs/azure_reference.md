# Quick Reference – Using vfxt.py

This section gives an overview of how to create Avere clusters in a Microsoft Azure environment.

> **SETUP NOTES:** A wizard for creating an Avere vFXT for Azure clusters is available in the Azure Marketplace. Read the [Avere vFXT for Azure documentation](https://docs.microsoft.com/azure/avere-vfxt/) for more complete information about the template-based deploy and additional preconfiguration required. The deployment wizard  automates most of these steps.
> Setup instructions without using a controller can be found [here](setup.md).

## Choosing authentication:

There are three options for authenticating.
1. the azure-cli to authenticate as an individual user
2. system assigned managed identity
3. service principal

The authentication method chosen must have the ability to create and manage clusters in a resource group.

### 1. Using the azure-cli as a user (recommended) (required for remote consoles)

To authenticate:

```bash
az login # login as a user OR
az login --identity # login with a system managed identity
```

Since you used the azure-cli, add the `--from-environment` flag to your vfxt.py command.

### 2. Using a system assigned managed identity

If you are using a controller and created a system assigned managed identity during setup, or if you followed the steps in [setup.md](setup.md) to create a VM
with the system assigned managed identity enabled, add the `--on-instance` flag to your vfxt.py command. The system assigned managed identity should have `Owner` permissions on its resource group.
Skip the rest of this section.

If you've got an Avere controller or other instance that doesn't have a system assigned managed identity, navigate to the instance in the portal, click on `Identity` in the left sidebar, turn `Status` to `On`, and assign the role `Owner` over the resource group. Owner is required to assign roles.

Read more in the [Azure Managed Service Identity documentation](https://docs.microsoft.com/azure/app-service/app-service-managed-service-identity).

### 3. Using a service principal

This is a more complicated strategy and should only be used when managed identities or the azure-cli cannot be used. It can be used both remotely or on an Azure instance.

To use this option, you must create a service principal specifically for cluster creation and administration, then provide that SP’s credentials to authenticate. Read the Azure documentation about [creating service principals for access control](<https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli>).

Give the service principal `Owner` permissions on the resource group.

Add the following commands to your vfxt.py command:

```bash
--subscription-id 'subscription'
--tenant-id 'tenant'
--application-id 'client_id' # from the service principal
--application-secret 'password'
```

## Azure Environment Options

Required environment options for each vfxt.py command in Azure include the resource group, location, network, and subnet. If you are using Blob storage as a backend cloud core filer, you must also specify the storage account.

```bash
vfxt.py
 --create                                 \
 --from-environment                       \
 --subscription-id      "subscsription"   \
 --azure-network        "vnet"            \
 --azure-subnet         "subnet"          \
 --location             "region"          \
 --resource-group       "resource_group"  \
 --cluster-name         "cluster_name"    \
 --admin-password       "admin_password"  \
 --storage-account      "storage_account" \
 --instance-type        "instance_type"   \
 {[--on-instance] OR [--from-environment] OR [--subscription-id,--tenant-id,--application-id,--application-secret]}
```

## Extra Azure Configuration Options

Refer to [Azure Options](azure_options.md) or `vfxt.py --help` for details. Extra configuration options for Azure cloud environments include:

* Security groups
* Tagging
* Data disk and root disk caching
* Boot diagnostics
* Additional resource groups

## Azure Cluster Settings

This table shows example values that can be used when creating an Avere vFXT cluster for Azure. Please work with your Technology Solutions or support representative to determine the best options.

|   | vfxt.py script option | Default value | Other value options |
| ---------- | ---------- | ------------------ | ---------- |
| VM instance type | `--instance-type` | `Standard_E32s_v3` | |
| Node cache size | `--node-cache-size` | `1024` | `4096`, `8192` |
| Number of nodes | `--nodes` | `3` | `6` |
| **Storage options:** ||||
| Defer creating storage | `--no-corefiler` | Omit this option  | `--no-corefiler` |
| Specify storage resource group  | `--storage-resource-group` | Omit this option if storage is in the same resource group as the cluster  | *group_name* |
| Specify existing empty container  | `--azurecontainer` | Omit this option (a new container is created by default) | *storage_acct/container_name* |

## Optional: Creating a non-default Cluster Runtime Role in Azure Active Directory

The Avere vFXT for Azure uses [role-based access control (RBAC)](https://docs.microsoft.com/azure/role-based-access-control/index) to authorize cluster VMs to perform certain tasks. The cluster controller uses the built-in role [Avere Contributor](https://docs.microsoft.com/azure/role-based-access-control/built-in-roles#avere-contributor) and the cluster nodes use the built-in role [Avere Operator](https://docs.microsoft.com/azure/role-based-access-control/built-in-roles#avere-operator).

   **NOTE:** The built-in roles are recommended. Do not create a customized role unless you have experience with the Azure Active Directory access control system.

If you want to use a customized operator role, you must define it before you create the cluster. Use the option [``--azure-role``](azure_options.md#azure-environment-options) to include it in the cluster create command.

This section explains how to create a custom role. It does not explain what statements to include - the example role definition here is the same as the built-in role Avere Operator. If creating a custom role, keep in mind that each cluster node needs the ability to access other vFXT nodes, to manage network infrastructure, and to modify storage resources.

The cluster nodes role should be scoped to the subscription that you will use for the cluster. Include your subscription ID in the `AssignableScopes` statement.

Save the role in a .json file (for example, avereclustercustom.json).

```json
{
    "AssignableScopes": [ "/subscriptions/your-subscription-ID" ],
    "Name": "avere-cluster-custom",
    "IsCustom": "true",
    "Description": "custom Avere cluster runtime role",
    "NotActions": [],
    "Actions": [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/virtualNetworks/read",
        "Microsoft.Network/virtualNetworks/subnets/read",
        "Microsoft.Network/virtualNetworks/subnets/join/action",
        "Microsoft.Network/networkSecurityGroups/join/action",
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
`az role definition create --role-definition avereclustercustom.json`

When you issue the vfxt.py `--create` command, pass the custom role name (from the `Name` value in the .json file) in the `--avere-role` argument.

Example:

```bash
vfxt.py --from-environment \
--resource-group "group"  --location "location" \
--azure-network "network" --azure-subnet "subnet" \
--create \
--cluster-name "name" --admin-password "password" \
--instance-type "type" --node-cache-size "size" \
--azure-role avere-cluster-custom  \
--storage-account "account_name"
```

If you exclude the role name in the create command, vfxt.py uses the default role, [Avere Operator](https://docs.microsoft.com/azure/role-based-access-control/built-in-roles#avere-operator). If the vfxt.py user does not have sufficient permissions to create the role, the cluster creation will fail.
