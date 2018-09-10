# Cloud cluster management with vfxt.py

The vfxt.py script is a command-line tool for creating, managing, and decommissioning Avere vFXT clusters in cloud-based virtual computing environments. It is supported on Microsoft Azure, Amazon Web Services, and Google Cloud Platform.

This documentation set gives a basic overview of the vfxt.py script and its options. For a more comprehensive explanation of how to set up a cloud project and configure the necessary infrastructure for running a vFXT cluster on a specific cloud platform, read the customized vFXT installation guide for your cloud provider, linked [below](#guides).

## Getting started

[About vfxt.py](about_vfxt_py.md)

[Installing and Setting Up the vfxt.py Script](installation.md)


## Syntax and options

[Using vftx.py](using_vfxt_py.md)

[Command Syntax and Options](syntax.md)

[All options](all_options.md)

## Platform-specific information

Microsoft Azure: 
* [Quick reference - Using vfxt.py with Microsoft Azure](azure_reference.md)
* [Azure-only command options](azure_options.md)

Amazon Web Services: 

* [Quick reference - Using vfxt.py with Amazon Web Services](aws_reference.md)
* [AWS-only options](aws_options.md)

Google Cloud Platform: 

* [Quick reference - Using vfxt.py with Google Cloud Platform](gce_reference.md)
* [GCE-only options](gce_options.md)

## Getting help

[Troubleshooting and support](troubleshooting.md)

Additional documentation is available at [library.averesystems.com](<http://library.averesystems.com/>) 

## About the vfxt.py script

The vfxt.py script is a command-line tool for creating and managing Avere clusters in cloud-based virtual computing environments. The script can create new Avere clusters - including creating the vFXT nodes that make up the cluster and establishing cloud storage as core filers; destroy existing clusters (including the vFXT nodes); create and add new nodes to a cluster; and do basic cluster configuration tasks. 

For ongoing cluster administration, use the Avere Control Panel. Read the Avere cluster [Configuration Guide](<http://library.averesystems.com/#operations>) for more details. 

The vfxt.py script can be used with any of the cloud computing providers that Avere OS supports. Environment setup requirements are different for the different platforms, and the exact commands available vary by cloud computing provider.

<a name="guides"></a>This document gives a basic overview of the vfxt.py script and its options. It includes information about commands specific to Microsoft Azure, Amazon Web Services, and Google Cloud Platform cloud services. However, setting up a cloud project and configuring it to provide an Avere vFXT cluster includes many more steps than are documented here. Project creation, identity and access management, networking, quota and billing concerns, security, and many other topics are explained in detail in the Avere vFXT Installation Guide customized for your cloud provider. Read the complete details here: 

* [vFXT Installation Guide for Amazon Web Services](<http://library.averesystems.com/#vfxt>) 
* [vFXT Installation Guide for Google Cloud Platform](<http://library.averesystems.com/#vfxt>)
* vFXT Installation Guide for Microsoft Azure – coming soon; read current online documentation [here](<http://aka.ms/averedocs>). 

The command `vfxt.py --help` gives a full list of command options, including provider-specific functionality. 

