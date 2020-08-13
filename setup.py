# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
import logging
from setuptools import setup

logging.basicConfig(level=logging.WARNING)

version = {}
with open("vFXT/version.py") as f:
    exec(f.read(), version) #pylint: disable=exec-used

base_deps = ['future', 'requests']
aws_deps = ['boto']
gce_deps = ['oauth2client', 'google-api-python-client']
azure_deps = ['requests-oauthlib', 'adal==1.2.4', 'azure-cli-core==2.10.1', 'azure-common==1.1.25', 'azure-mgmt-authorization==0.60.0', 'azure-mgmt-compute==13.0.0', 'azure-identity==1.3.1', 'azure-mgmt-msi==1.0.0', 'azure-mgmt-network==11.0.0', 'azure-mgmt-resource==10.1.0', 'azure-mgmt-storage==11.1.0', 'azure-storage-blob==12.4.0', 'azure-storage-queue==12.1.2', 'azure-storage-common==2.1.0', 'knack==0.7.2', 'msrest==0.6.18', 'msrestazure==0.6.4']

setup(name='vFXT',
    version=version['__version__'],
    description='''The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility''',
    long_description='''The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility
provide the ability to create, extend, destroy, start, and stop vFXT clusters in
all supported cloud environments.

Licensed under the MIT license.''',
    url='http://www.averesystems.com',
    author='Jason Woodward',
    author_email='woodwardj@averesystems.com',
    license='MIT',
    install_requires = base_deps + aws_deps + gce_deps + azure_deps,
    packages=['vFXT'],
    test_suite="tests",
    scripts=['vfxt.py'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
)
