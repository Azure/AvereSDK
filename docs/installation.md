
# Installing and Setting Up the vfxt.py Script

You can run vfxt.py from any UNIX-style console environment that has access to your cloud computing resources. The simplest option is to create a Linux instance within the cloud environment, and install vfxt.py in that virtual machine. Alternatively, you can use a console from a remote Linux or Mac OS environment, as long as it has IP connectivity to your cloud instances. 

> Tip: For Microsoft Azure, a preconfigured Cluster Controller Node virtual machine image is available in the Azure Marketplace. Search for “Avere” and then choose **Avere vFXT for Azure**. This image is preconfigured with required software to create and manage Avere vFXT clusters in Azure.  
> 
> The Azure Marketplace also has the **Avere vFXT for Azure template**, which is a wizard-based cluster creation tool. That process is described in [Avere vFXT for Azure documentation](https://docs.microsoft.com/en-us/azure/avere-vfxt/).

## Cloud Console Setup

If setting up a Linux instance in the cloud, follow these guidelines. 

* Create a VM instance of any size.
* The instance must have the privileges to create other instances. Read the requirements for your cloud provider to learn how to configure the VM that provides your vfxt.py console. 
* Install a recent Linux distribution from GNU, Debian, or a similar provider. Follow the instructions in [vfxt.py Software Requirements](#vfxtpy-software-requirements), below, for installing additional required packages. 

## Remote Console Setup 

If using a console from a system outside the cloud environment, make sure it can access the instances within your cloud environment. Read your cloud provider’s documentation to learn how to use a VPN or other utility to provide IP connectivity to your cloud instances. 

Install the software described in [vfxt.py Software Requirements](#vfxtpy-software-requirements), below. 

## vfxt.py Software Requirements

Before using vfxt.py, make sure that your Linux environment includes all of the necessary software packages. 

> Note that recent distributions of Red Hat/CentOS do not include [required security packages](<https://azure.github.io/Avere/legacy/ops_guide/4_7/html/security_prereqs.html>). 

### 1. Check security prerequisites and Python version

The vfxt.py script requires Python version 2.7.9 or later. 

Also, the system used for creating and managing the vFXT cluster must meet the software security requirements for administering an Avere cluster, as described in the [appendix of the Avere OS Configuration Guide](<https://azure.github.io/Avere/legacy/ops_guide/4_7/html/security_prereqs.html>).

### 2. Update system dependencies 

In this step, make sure that the software needed to run vfxt.py is installed and configured in the shell system. Python, SSL, and a foreign function interface (FFI) package are required. The steps are different depending on the Linux distribution; consult your Linux documentation for details. 

For Ubuntu or another Debian-based Linux distribution, run these commands:

  ```bash
  sudo apt-get update 
  sudo apt-get install python-pip
  ```

<!-- * If using Red Hat Enterprise Linux or CentOS:       #RHEL/CentOS unsupported as of 9/2018

  ```bash
  sudo wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
  sudo rpm -ivh epel-release-latest-7.noarch.rpm
  sudo yum install -y python-pip
  ```
--> 

### 3. Update Python dependencies

Ensure that the Python installation has the latest versions of the API library for your cloud provider: 

* Boto AWS API library if using AWS 
* Azure Python SDK if using Azure
* Google API client library if using GCE

This command can be used with any of the three cloud providers to install the needed library. 

    pip install --user --upgrade boto requests google-api-python-client azure

> Note: The `azure` package is a meta-package that downloads a full set of Azure libraries. If you will not be working with Microsoft Azure, you can omit that term from the command. To install only the Azure packages, use `$ pip install –-user azure`


## Downloading and Installing vfxt.py

The vfxt.py script is published in the Python Package Index (PyPI) and also available from the Avere SDK GitHub page. 

The easiest way to install vfxt.py is by using pip to automatically download and install the script and dependencies:

    pip install --user vFXT

The `--user` option installs vfxt.py in `site.USER_BASE`, which defaults to `~/.local` on most UNIX-style systems. Read the [Python site.py documentation](<https://docs.python.org/2/library/site.html#site.USER_BASE>) to learn more.  

Release archives also are available from <https://github.com/Azure/AvereSDK/releases>. (This is the same release available with pip but in a standalone archive format.)

You can test that the script is active by issuing the help command.

    vfxt.py --help

If you see the help text, the test was successful. If you do not see the vfxt.py help text, check the software requirements and try the installation again. 

## Configuring the Cloud Environment 

Before you can use vfxt.py to create or modify Avere clusters, you must have a cloud account set up with a supported provider, and appropriate environment configuration. 

Regardless of whether you use vfxt.py on a virtual machine inside your cloud environment, or from a console outside the cloud, the following basic requirements apply: 

* vfxt.py must be able to make contact with the cloud provider's API endpoints. A proxy service might be required. 
* vfxt.py must be able to authenticate to the cloud environment. 
* vfxt.py must have permission to create and destroy virtual machine instances in the cloud environment. 

The details vary greatly by cloud provider. Read the detailed Avere vFXT Installation Guide for your cloud compute provider for complete information about setting up projects, network configuration, security and privileges, and other vital information before attempting to use vfxt.py. 

* [vFXT Installation Guide for Amazon Web Services](<https://azure.github.io/Avere/#vfxt>)
* [vFXT Installation Guide for Google Cloud Platform](<https://azure.github.io/Avere/#vfxt>)
* vFXT Installation Guide for Microsoft Azure (vfxt.py version in development, read current documentation [here](<https://docs.microsoft.com/en-us/azure/avere-vfxt/avere-vfxt-deploy-plan>))

These sections of this documentation also give provider-specific information about using vfxt.py on particular cloud systems. 
* [Quick Reference - Using vfxt.py with Amazon Web Services](aws_reference.md)
* [Quick Reference - Using vfxt.py with Google Cloud Platform](gce_reference.md) 
* [Quick Reference – Using vfxt.py with Microsoft Azure](azure_reference.md)

## Next Step - Basic vfxt.py Syntax 
 
After you have installed the software on your system, read [Using vfxt.py](using_vfxt_py.md) to learn the basics of issuing commands.
