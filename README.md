Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.

Copyright (c) Microsoft Corporation. All rights reserved.

The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility
provide the ability to create, extend, destroy, start, and stop vFXT clusters in
all supported cloud environments.

Licensed under the MIT License.

# User Guide

You can find the user documentation in this repository under [docs](/docs/README.md).


# Installation

## With pip

```pip install vFXT```

## From source

Use pip within the source directory to install all of the required dependencies.
The use of `--user` is encouraged.  This installs the script `vfxt.py` in
`~/.local/bin` on Unix (`~/Library/Python/{major.minor}/bin` on Mac) and
`%APPDATA%/Python/Python{major minor}/bin` on Windows.  This path will
need to be added to the PATH environment variable.

```pip install --user .```

## Authentication requirements - specific for each service backend

- Azure: requires an AD application/service principal

# vFXT Library

## Azure example:

    from vFXT.cluster import Cluster
    from vFXT.msazure import Service

    azure = Service(subscription_id='', tenant_id='',
        application_id='', application_secret='',
        resource_group='', storage_account='',
        location='', network='', subnet='',
    )
    cluster = Cluster.create(azure, 'Standard_D16s_v3', 'averecluster', 'PLACEHOLDER')

    with open('/home/user/.ssh/id_rsa.pub','r') as f: # must be rsa
        sshpubkey = f.read()
    client = ServiceInstance.create(azure, 'Standard_DS1', 'client1', 'debian:debian-10:10:latest', admin_ssh_data=sshpubkey)

## General example:

To load an existing, running cluster:

    Cluster.load(service, mgmt_ip='fill me in', admin_password='fill me in')

To instantiate a cluster that may be offline:

    cluster = Cluster(gce, nodes=['xxx', 'xxx', 'xxx'], admin_password='xxx', mgmt_ip='xxx')
    if cluster.is_off():
      cluster.start()
    elif not cluster.is_on() and not cluster.is_off()
      # some nodes are offline, some are online
      cluster.status()

To serialize a cluster:

    import json
    json.dumps(cluster.export())

    cluster.export() emits
    {'nodes': [u'node-1', u'node-3', u'node-2'], 'admin_password': 'pass', 'mgmt_ip': '10.1.1.1'}

    # To recreate the object:
    cluster = Cluster(service, **{'nodes': [u'node-1', u'node-3', u'node-2'], 'admin_password': 'pass', 'mgmt_ip': '10.1.1.1'})

    # The same with your service object:
    service_data = service.export()
    service = Service(**service_data)

# Testing

Run the unit test suite

    python setup.py test

Or run one test at a time

    python setup.py test -s tests.GCE_test

The unittest configuration is found in tests/test_config.json.  Set up credentials and existing infrastructure to verify against in the configuration prior to running.

# Example vfxt.py utility invocation

The first part of the invocations are the cloud-type and the authentication options.  Following those, the action and any related action options.

## Azure examples

### Azure create a cluster

    vfxt.py --cloud-type azure \
    --subscription-id 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
    --client-id 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
    --client-secret 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' \
    --tenant-id 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' \
    --resource-group xxxxxxxxxxxx \
    --azure-network net --azure-subnet subnet --location eastus --resource-group rg \
    \
    --create                                \
    --cluster-name avereclustrer  \
    --admin-password PLACEHOLDER              \
    --nodes 3                               \
    --instance-type 'Standard_D16s_v3' \
    --azure-role "avere-cluster"

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
