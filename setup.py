# Copyright (c) 2015-2020 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
import logging
from setuptools import setup

logging.basicConfig(level=logging.WARNING)

version = {}
with open("vFXT/version.py") as f:
    exec(f.read(), version) #pylint: disable=exec-used

base_deps = ['future', 'requests']
# Add azure-cli installation here when this GitHub issue is resolved: https://github.com/Azure/azure-cli/issues/23372
azure_deps = ['requests-oauthlib', 'adal', 'azure-cli-core', 'azure-common', 'azure-mgmt-authorization', 'azure-mgmt-compute', 'azure-identity', 'azure-mgmt-msi', 'azure-mgmt-network', 'azure-mgmt-resource', 'azure-mgmt-storage', 'azure-storage-blob', 'azure-storage-queue', 'azure-storage-common', 'knack', 'msrest', 'msrestazure']

setup(name='vFXT',
    version=version['__version__'],
    description='''The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility''',
    long_description='''The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility
provide the ability to create, extend, destroy, start, and stop vFXT clusters in
all supported cloud environments.

Licensed under the MIT license.''',
    url='https://github.com/Azure/AvereSDK',
    author='Jeff Bearer',
    author_email='jebearer@microsoft.com',
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
