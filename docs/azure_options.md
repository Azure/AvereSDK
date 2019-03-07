# Azure Command Options 

These options can be used only if the `--cloud-type` value is `azure`. 

## Azure Authentication Options 

|<img width=300/> | |
| ---------- | ------------------ |
| `--subscription-id` *ID* | Azure subscription identifier |
| `--application-id` *ID* | UUID for the service principal |
| `--tenant-id` *tenant_ID* | Active Directory application tenant identifier |
| `--application-secret` *password*  | Password for the AD service principal (if needed, see [Service Principal Authentication Option](azure_reference.md#service-principal-authentication-option) for details) |

Use the generic option `--on-instance` for local console commands. 

## Azure Environment Options

| <img width=500/>  | |
| ---------- | ------------------ |
| `--azure-network` *vnet_name* | Virtual network that houses the cluster nodes |
| `--azure-subnet` *subnet_name* | Subnet in the virtual network  |
| `--azure-role` *role_name* | Existing Azure role for the cluster. If not supplied, a role will be created, or cluster creation will fail if permissions are insufficient to create the role. |
| `--location` *location_shortname*    | Azure geographic location |
| `--network-resource-group` *group_name* | Network resource group (if different from the resource group used for the cluster VMs) |
| `--resource-group` *group_name* | Resource group for the cluster VMs |
| `--storage-account` *account_ID* | Azure storage account for this cluster |
| `--storage-resource-group` *group_name*  | Storage resource group (if different from the resource group used for the cluster VMs) |
| `--application-id` *ID_number* | Active Directory service principal ID, used with `--application-secret` to authenticate if using Service Principal authentication |
| `--application-secret` *password* | Active Directory service principal password; used with `--application-id` to authenticate if using Service Principal authentication |

## Additional Azure-Specific Options 

| <img width=600/>  | |
| ---------- | ------------------ |
| `--azurecontainer` [*storage_acct*/*container_name*] | Specify an existing container to use instead of creating a new one. The container must be empty. |
| `--azure-instance-addresses` *instance1_ID* *instance2_ID* *instance3_ID* [*... instanceN_ID*] | Specific instance addresses to use rather than assigning them dynamically. Separate addresses with spaces. |
| `--azure-tag` *tag* |  Azure instance tag |
| `--data-disk-caching` {`ReadOnly`,`ReadWrite`} | Azure data disk caching mode (defaults to `ReadOnly`) |
| `--enable-boot-diagnostics` | Use Azure instance boot diagnostics (off by default). Specify a storage account in `--storage-account` where the diagnostic information will be written. |
| `--network-security-group` *group_name* |  Name of the network security group (if needed) |
| `--root-disk-caching` {`ReadOnly`,`ReadWrite`} | Azure root disk caching mode (defaults to `ReadOnly`) |
| `--storage-account` *account_ID* | Storage account for Blob-backed core filer and boot diagnostics |
| **XXX review below XXX**  | | 
| `--azure-government` | Use the default base URL and storage suffix for the Azure Government Cloud environment  |
| `--azure-endpoint-base-url` | Specify the base URL of the API endpoint for a non-public Azure environment | 
| `--azure-storage-suffix` | Specify the storage suffice for a non-public Azure environment | 
| `--avere-container-not-empty` | Use the specified storage endpoint, which has existing Avere-formatted data **XXX is this right? XXX**  | 
| `--disable-azure-container-encryption` | Don't allow encryption for objects written to the storage endpoint | 
| `--disable-azure-container-compression` | Don't allow compression for objects written to the storage endpoint |
| `--disable-azure-container-https` | Don't use HTTPS for communication with the storage endpoint |
| `--disable-azure-container-https-verify` | Don't verify encryption certificates for communication with the storage endpoint |


## Additional Azure Information

Read [Quick Reference - Using vfxt.py with Microsoft Azure](azure_reference.md) for more Azure-specific information.  
