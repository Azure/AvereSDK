# Installing and Setting Up the vfxt.py script

> **TIP:** This is not required if you are running vfxt.py from an Avere Controller VM. The cluster Controller Node virtual machine image is available in the Azure Marketplace. Search for “Avere” and then choose **Avere vFXT for Azure**. This image is preconfigured with required software to create and manage Avere vFXT clusters in Azure. See [Avere vFXT for Azure documentation](https://docs.microsoft.com/azure/avere-vfxt/) for more details.

You can run vfxt.py from any UNIX-style console environment that has access to your cloud computing resources. The simplest option is to create a Linux instance within the cloud environment, and install vfxt.py in that virtual machine. Alternatively, you can use a console from a remote Linux or Mac OS environment, as long as it has IP connectivity to your cloud instances.

> **NOTE:** If creating an Azure VM for vfxt.py commands, you can use any instance type that can run a Linux operating system for command-line access; it does not need much processing power or storage. You can choose a general purpose A0 or A1 VM with HDD type disks. The VM should be created from the same subscription that you will use to create the cluster.

## Azure VM Setup

```bash
SUBSCRIPTION="subscription"
TENANT="tenant"
RESOURCE_GROUP="resource_group"
LOCATION="region"
VNET="vnet_name"
TYPE="type" # see here: https://azure.microsoft.com/en-us/pricing/details/virtual-machines/linux/

IMAGE="Canonical:0001-com-ubuntu-server-focal:20_04-lts:latest" # or some other Ubuntu image

# set the correct account
az account set -s "$SUBSCRIPTION"

# create the resource group
az group create -n "$RESOURCE_GROUP" -l "$LOCATION"

# create a vnet
az network vnet create -g "$RESOURCE_GROUP" -n "$VNET"

# create a subnet
az network vnet subnet create -n "$SUBNET" -g "$RESOURCE_GROUP" --vnet-name "$VNET"

# create a storage account
az storage account create -g "$RESOURCE_GROUP" -n "$STORAGE"

# create the VM, passing it the VNET and subnet you've created
# if you are planning to authenticate with --on-instance (system assigned managed identity), run the above with the following
# --assign-identity --role contributor --scope /subscriptions/$SUBSCRIPTION/resourceGroups/$RESOURCE_GROUP
az vm create --vnet-name "$VNET" --subnet "$SUBNET" -n "$VM_NAME" -l "$LOCATION" -g "$RESOURCE_GROUP" --image "$IMAGE"
```

The instance must have the privileges to create other instances, either through a managed identity, user authentication, or a service principal.

Follow the instructions in [vfxt.py Software Requirements](#vfxtpy-software-requirements), below, for installing additional required packages.

## Remote Console Setup

If using a console from a system outside the cloud environment, make sure it can access the instances within your cloud environment.

Install the software described in [vfxt.py Software Requirements](#vfxtpy-software-requirements), below.

## vfxt.py Software Requirements

Before using vfxt.py, make sure that your Linux environment includes all of the necessary software packages.

### 1. Check security prerequisites and Python version

The vfxt.py script requires Python 3.

Also, the system used for creating and managing the vFXT cluster must meet the software security requirements for administering an Avere cluster, as described in the [appendix of the Avere OS Configuration Guide](<https://azure.github.io/Avere/legacy/ops_guide/4_7/html/security_prereqs.html>).

### 2. Update system dependencies

In this step, make sure that the software needed to run vfxt.py is installed and configured in the shell system. Python, SSL, and a foreign function interface (FFI) package are required. The steps are different depending on the Linux distribution; consult your Linux documentation for details.

For Ubuntu or another Debian-based Linux distribution, run these commands:

```bash
sudo apt-get update
sudo apt-get install python-pip
sudo apt-get install azure-cli # if using `--from-environment` authentication
sudo apt-get install python3-venv # if using a python virtual environment to run vfxt.py
```

## Downloading and Installing vfxt.py

> **NOTE:** vfxt.py on PyPI is now deprecated. To get HOL vfxt.py, install directly from the GitHub repo.

> **TIP:** using a python virtual environment is recommended. If a virtual environment is not used, utilizing `--user` when vfxt.py is recommended.

The easiest way to install vfxt.py is by using pip to automatically download and install the script and dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
(.venv): python3 -m pip install git+https://github.com/Azure/AvereSDK.git
```

**Using `--user`**

If you choose to install outside of a virtual environment, it is recommended you use the `--user` flag.

The `--user` option installs vfxt.py in `site.USER_BASE`, which defaults to `~/.local` on most UNIX-style systems. Read the [Python site.py documentation](<https://docs.python.org/2/library/site.html#site.USER_BASE>) to learn more.

Release archives also are available from <https://github.com/Azure/AvereSDK/releases>. (This is the same release available with pip but in a standalone archive format.)

```bash
python3 -m pip install --user git+https://github.com/Azure/AvereSDK.git
```

## Verify installation

You can test that the script is active by issuing the help command.

```bash
vfxt.py --help
```

If you see the help text, the test was successful. If you do not see the vfxt.py help text, check the software requirements and try the installation again.

## Configuring the Cloud Environment

Before you can use vfxt.py to create or modify Avere clusters, you must have a cloud account set up with Azure, and appropriate environment configuration.

Regardless of whether you use vfxt.py on a virtual machine inside your cloud environment, or from a console outside the cloud, the following basic requirements apply:

* vfxt.py must be able to make contact with the cloud provider's API endpoints. A proxy service might be required.
* vfxt.py must be able to authenticate to the cloud environment.
* vfxt.py must have permission to create and destroy virtual machine instances in the cloud environment.

> Read the detailed [Avere vFXT Installation Guide](https://docs.microsoft.com/azure/avere-vfxt/avere-vfxt-deploy-plan) for complete information about setting up projects, network configuration, security and privileges, and other vital information before attempting to use vfxt.py.

* [Quick Reference – Using vfxt.py with Microsoft Azure](azure_reference.md)

## Next Step - Basic vfxt.py Syntax

After you have installed the software on your system and setup permissions and networking, read [Using vfxt.py](using_vfxt_py.md) to learn the basics of issuing commands.
