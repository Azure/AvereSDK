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

- AWS: requires the access key/secret access key pair
- Azure: requires an AD application/service principal
- GCE: requires a service account with the JSON key file

# vFXT Library

## AWS example:

    from vFXT.cluster import Cluster
    from vFXT.aws import Service

    aws = Service(region='fill me in', access_key='fill me in', subnet='subnet-f66a618e', secret_access_key='fill me in')

    cluster = Cluster.create(aws, 'r3.8xlarge', 'averecluster', 'PLACEHOLDER')
    try:
      cluster.make_test_bucket(bucketname='averecluster-s3bucket', corefiler='averecluster-s3bucket')
      cluster.add_vserver('vserver')
      cluster.add_vserver_junction('vserver', 'averecluster-s3bucket')
    except Exception as e:
      ...

    from vFXT.serviceInstance import ServiceInstance
    # via ServiceInstance which calls the backend .create_instance()
    client = ServiceInstance.create(aws, 'c3.xlarge', 'client1', 'ami-b9faad89', key_name="aws_ssh_keyname")

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

## GCE example:

    from vFXT.cluster import Cluster
    from vFXT.gce import Service

    gce = Service(client_email='fill me in', key_file='path-to.json', zone='us-central1-b', project_id='fill me in', network_id='fill me in')
    cluster = Cluster.create(gce, 'n1-highmem-8', 'averecluster', 'PLACEHOLDER')
    cluster.stop()
    cluster.destroy()

    with open('/home/user/.ssh/id_rsa.pub','r') as f:
      sshpubkey=f.read()
      sshpubkey='username:{}'.format(sshpubkey)

    from vFXT.serviceInstance import ServiceInstance
    # via ServiceInstance which calls the backend .create_instance()
    client = ServiceInstance.create(gce, 'n1-standard-1', 'client1', 'projects/debian-cloud/global/images/debian-10-buster-v20200210', metadata={'ssh-keys':sshpubkey}, tags=['client'])

    client_instance.destroy()

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

##  AWS examples

### AWS create a cluster

    vfxt.py --cloud-type aws --region us-west-2 --access-key 'X' \
    --secret-key 'X' --subnet subnet-f99a618e \
    --placement-group perf1 \
    \
    --create                                \
    --cluster-name avereclustrer  \
    --admin-password PLACEHOLDER              \
    --nodes 3                               \
    --instance-type 'r4.2xlarge'

### AWS destroy a cluster

    vfxt.py --cloud-type aws --region us-west-2 --access-key 'X' \
    --secret-key 'X' --subnet subnet-f66a618e \
    --placement-group perf1 \
    \
    --destroy                         \
    --management-address 10.50.248.50 \
    --admin-password PLACEHOLDER

### AWS add nodes

    vfxt.py --cloud-type aws --region us-west-2 --access-key 'X' \
    --secret-key 'X' --subnet subnet-f99a618e \
    --placement-group perf1 \
    \
    --add-nodes                       \
    --nodes 3                         \
    --management-address 10.50.248.50 \
    --admin-password PLACEHOLDER

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
    --instance-type 'Standard_E32s_v3' 

## GCE examples

### GCE create a cluster

    vfxt.py --cloud-type gce \
    --key-file=service-account.json \
    --project fine-volt-704 --zone us-central1-b --network gce1 \
    \
    --create                                \
    --image-id vfxt-4614                    \
    --admin-password PLACEHOLDER              \
    --cluster-name averecluster  \
    --nodes 3                               \
    --gce-tag use-nat                       \
    --instance-type 'n1-highmem-8'

### GCE destroy a cluster

    vfxt.py --cloud-type gce \
    --key-file=service-account.json \
    --project fine-volt-704 --zone us-central1-b --network gce1 \
    \
    --destroy                         \
    --management-address 10.52.16.103 \
    --admin-password PLACEHOLDER

### GCE add nodes

    vfxt.py --cloud-type gce \
    --key-file=service-account.json \
    --network gce1 \
    --project fine-volt-704 --zone us-central1-a \
    \
    --add-nodes                       \
    --nodes 3                         \
    --management-address 10.52.16.115 \
    --admin-password 'PLACEHOLDER'

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
