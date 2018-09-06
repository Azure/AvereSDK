# Creating and managing vFXT clusters - About the vfxt.py script

The vfxt.py script is a command-line tool for creating and managing Avere clusters in cloud-based virtual computing environments. The script can create new Avere clusters - including creating the vFXT nodes that make up the cluster and establishing cloud storage as core filers; destroy existing clusters (including the vFXT nodes); create and add new nodes to a cluster; and do basic cluster configuration tasks. 

For ongoing cluster administration, use the Avere Control Panel. Read the Avere Cluster [Configuration Guide](<http://library.averesystems.com/#operations>) for more details. 

The vfxt.py script can be used with any of the cloud computing providers that Avere OS supports. Environment setup requirements are different for the different platforms, and the exact commands available vary by cloud computing provider.

This document gives a basic overview of the vfxt.py script and its options. It includes information about commands specific to Microsoft Azure, Amazon Web Services, and Google Compute Project cloud services. However, setting up a cloud project and configuring it to provide an Avere vFXT cluster includes many more steps than are documented here. Project creation, identity and access management, networking, quota and billing concerns, security, and many other topics are explained in detail in the Avere vFXT Installation Guide customized for your cloud provider. Read the complete details here: 

* [vFXT Installation Guide for Amazon Web Services](<http://library.averesystems.com/#vfxt>) 
* [vFXT Installation Guide for Google Cloud Platform](<http://library.averesystems.com/#vfxt>)
* vFXT Installation Guide for Microsoft Azure – coming soon; read current online documentation [here](<http://aka.ms/averedocs>). 

The command `vfxt.py --help` gives a full list of command options, including provider-specific functionality. 
