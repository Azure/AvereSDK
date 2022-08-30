# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
import logging
from setuptools import setup

logging.basicConfig(level=logging.WARNING)

version = {}
with open("vFXT/version.py") as f:
    exec(f.read(), version) #pylint: disable=exec-used

base_deps = ['future', 'requests']
azure_deps = ['requests-oauthlib', 'adal==1.2.7', 'azure-cli-core==2.39.0', 'azure-common==1.1.28', 'azure-mgmt-authorization==2.0.0', 'azure-mgmt-compute==27.1.0', 'azure-identity==1.10.0', 'azure-mgmt-msi==6.0.1', 'azure-mgmt-network==20.0.0', 'azure-mgmt-resource==21.1.0b1', 'azure-mgmt-storage==20.0.0', 'azure-storage-blob==12.11.0', 'azure-storage-queue==12.2.0', 'azure-storage-common==2.1.0', 'knack==0.9.0', 'msrest==0.7.1', 'msrestazure==0.6.4']

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
    install_requires = base_deps + azure_deps,
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
        'Programming Language :: Python :: 3',
    ],
)
