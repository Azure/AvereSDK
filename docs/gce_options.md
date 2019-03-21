# GCE Options 

These options can be used only if the `--cloud-type` value is `gce`. 

## GCE Authentication Options 

| <img width=500/>  | |
| ---------- | ------------------ |
| `--client-email` *email_address* | OATH2 service account client email for p12 key files (older option for off-instance authentication) |
| `--key-file` *key_file_path*  | OATH2 service account P12 (deprecated) or JSON key file for off-instance authentication. For P12 keys, you must also provide the client email address with `--client-email` |

Use the generic option `--on-instance` for local console commands. 

## GCE Environment Options

| <img width=300/> | |
| ---------- | ------------------ |
| `--network` *network_name* | Network name |
| `--subnetwork` *subnetwork_name* | Subnetwork name |
| `--zone` *GCE_zone* [*zone2* ...] | One or more zone names (example: us-central1-a). Separate multiple names with spaces. |

## Additional GCE-Specific Options 

| <img width=800/> | |
| ---------- | ------------------ |
| `--gce-tag` *GCE_instance_tag* | GCE instance tag |
| `--instance-addresses` *inst1_addr* *inst2_addr* *inst3_addr* [... *instN_addr*] | Instance addresses to assign to the cluster nodes. Separate addresses with spaces.   |
| `--local-ssd`  | Use local-ssd disks for cache     |
| `--metadata` *key1*:*value1* *key2*:*value2* ... | Set one or more metadata values on the instances being created |
| `--network-project` *project_name* | Specifies the host project name for a Shared VPC configuration |
| `--project` *project_name* | Google Cloud project name |
| `--scopes` *scope1* [*scope2* ...] | GCE scopes to assign to the cluster nodes (separate multiple scopes with spaces) |
| `--service-account` *account_name* | Specifies a nondefault service account for the cluster nodes to use. Use this option with `--create`.    |
| `--storage-class` *class_name* | Specify the storage class for a bucket at creation time. Options include STANDARD, NEARLINE, DURABLE_REDUCED_AVAILABILITY, MULTI_REGIONAL, REGIONAL, and COLDLINE. |


## Additional Google Compute Engine Information

Read [Quick Reference - Using vfxt.py with Google Cloud Platform](gce_reference.md) for more GCE-specific information. 
