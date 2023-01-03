Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.

Copyright (c) Microsoft Corporation. All rights reserved.

The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility
provide the ability to create, extend, destroy, start, and stop vFXT clusters in
all supported cloud environments.

Licensed under the MIT License.

# Absolute fastest way to get started

Find more detailed user documentation in this repository under [docs](/docs/README.md).

## 1. Create a controller VM

Make a preconfigured Cluster Controller Node virtual machine. It has vfxt.py and all necessary packages pre-installed.

The Azure Marketplace also has the **Avere vFXT for Azure ARM template documentation**, which is a wizard-based cluster creation tool. That process is described in [Avere vFXT for Azure documentation](https://docs.microsoft.com/azure/avere-vfxt/).

## 2. Connect and login

Login with the azure-cli.

```bash
az login
```

## Run vfxt.py

This relies on the default values in the script:
- nodes: 3
- node cache: 1024

Set some variables:

```bash
SUBSCRIPTION="subscription"
TENANT="tenant"
RESOURCE_GROUP="resource_group"
LOCATION="region"
ADMIN_PASSWORD="admin_password"
CLUSTER_NAME="cluster_name"
VNET="vnet_name" # same vnet as controller
TYPE="Standard_E32s_v3"

STORAGE_ACCOUNT="storage_account_name"
# if this doesn't exist yet, run `az storage account create -g "$RESOURCE_GROUP" -n "$STORAGE_ACCOUNT"`

SUBNET="subnet_name"
# same subnet as controller; if this doesn't exist yet, run
# `az network vnet subnet create -n "$SUBNET" -g "$RESOURCE_GROUP" --address-prefixes "10.0.2.0/24" --vnet-name "$VNET"`
```

```bash
vfxt.py
    --create                                  \
    --from-environment                        \
    --cloud-type           azure              \
    --subscription-id      "$SUBSCRIPTION"    \
    --tenant-id            "$TENANT"          \
    --azure-network        "$VNET"            \
    --azure-subnet         "$SUBNET"          \
    --location             "$LOCATION"        \
    --resource-group       "$RESOURCE_GROUP"  \
    --cluster-name         "$CLUSTER_NAME"    \
    --admin-password       "$ADMIN_PASSWORD"  \
    --storage-account      "$STORAGE_ACCOUNT" \
    --instance-type        "$INSTANCE_TYPE"
```
