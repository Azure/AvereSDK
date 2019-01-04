# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
import logging
from setuptools import setup

logging.basicConfig(level=logging.WARNING)

version = {}
with open("vFXT/version.py") as f:
    exec(f.read(), version) #pylint: disable=exec-used

aws_deps = ['boto']
gce_deps = ['oauth2client', 'google-api-python-client']
azure_deps = ['requests', 'requests-oauthlib', 'adal==1.2.0', 'applicationinsights==0.11.5', 'azure-cli-core==2.0.41', 'azure-cli-nspkg==3.0.2', 'azure-common==1.1.13', 'azure-mgmt-authorization==0.50.0', 'azure-mgmt-compute==4.3.1', 'azure-mgmt-msi==0.2.0', 'azure-mgmt-network==2.4.0', 'azure-mgmt-nspkg==2.0.0', 'azure-mgmt-resource==2.0.0', 'azure-mgmt-storage==2.0.0', 'azure-nspkg==2.0.0', 'azure-storage-blob==1.4.0', 'azure-storage-common==1.4.0', 'azure-storage-nspkg==3.0.0', 'entrypoints==0.2.3', 'knack==0.3.3', 'msrest==0.6.2', 'msrestazure==0.4.34']

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
    install_requires = aws_deps + gce_deps + azure_deps,
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
    ],
)
