# Cloud Cluster Management with vfxt.py

The vfxt.py script is a command-line tool for creating and managing Avere clusters in cloud-based virtual computing environments.

This script has complete capabilities for creating and managing Avere vFXT clusters, including:

* Create a new Avere vFXT cluster - including creating the vFXT nodes that make up the cluster and configuring cloud storage as a backend core filer
* Destroy existing clusters (including the vFXT nodes)
* Create and add new nodes to a cluster
* Basic cluster configuration tasks

For ongoing cluster administration, use the Avere Control Panel. Read the Avere cluster [Configuration Guide](<https://azure.github.io/Avere/#operations>) for more details.

**NOTE:**
A previous version of this product supported AWS and GCE environments in addition to Microsoft Azure. These capabilities have been deprecated. Some commands related to those capabilities still appear in this documentation. Make sure you are using the specific commands documented for Microsoft Azure.

This document gives a basic overview of the vfxt.py script and its options. However, setting up a cloud project and configuring it to provide an Avere vFXT cluster includes many more steps than are documented here. Project creation, identity and access management, networking, quota and billing concerns, security, and many other topics are explained in detail in the [Avere vFXT Installation Guide](<https://aka.ms/averedocs>).

The command `vfxt.py --help` gives a full list of command options, including provider-specific functionality.

## Getting Started

[Installing and Setting Up the vfxt.py Script](installation.md)

## Syntax and Options

[Using vfxt.py](using_vfxt_py.md) - Detailed explanation of basic syntax and help for common tasks including these:

* [Create a cluster](using_vfxt_py.md#creating-a-cluster)
* [Add nodes to a cluster](using_vfxt_py.md#add-nodes-to-a-cluster)
* [Destroy a cluster](using_vfxt_py.md#destroy-a-cluster)

[Command Syntax and Options](syntax.md) - Descriptions for all script options

[All options](all_options.md) - Help-style list of options

## Command reference

* [Quick reference - Using vfxt.py with Microsoft Azure](azure_reference.md)
* [Azure-specific command options](azure_options.md)

## Getting Help

[Troubleshooting and support](troubleshooting.md)

Additional documentation is available at the [Avere legacy documentation page](<https://azure.github.io/Avere/>)
