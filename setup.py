# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
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
azure_deps = ['requests-oauthlib', 'adal==1.2.1', 'azure-cli-core==2.0.60', 'azure-cli-nspkg==3.0.3', 'azure-common==1.1.18', 'azure-mgmt-authorization==0.51.1', 'azure-mgmt-compute==4.4.0', 'azure-mgmt-msi==0.2.0', 'azure-mgmt-network==2.5.1', 'azure-mgmt-nspkg==3.0.2', 'azure-mgmt-resource==2.1.0', 'azure-mgmt-storage==3.1.1', 'azure-nspkg==3.0.2', 'azure-storage-blob==1.5.0', 'azure-storage-queue==1.4.0', 'azure-storage-common==1.4.0', 'azure-storage-nspkg==3.1.0', 'entrypoints==0.3', 'knack==0.5.3', 'msrest==0.6.4', 'msrestazure==0.6.0']

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
