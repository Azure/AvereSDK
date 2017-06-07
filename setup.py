# Copyright (c) 2015-2017 Avere Systems, Inc.  All Rights Reserved.
from setuptools import setup

version = {}
with open("vFXT/version.py") as f:
    exec(f.read(), version)

setup(name='vFXT',
    version=version['__version__'],
    description='''The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility''',
    long_description='''The Avere virtual FXT (vFXT) Python library and vfxt.py command line utility
provide the ability to create, extend, destroy, start, and stop vFXT clusters in
all supported cloud environments.

Licensed under the Apache License, Version 2.0.''',
    url='http://www.averesystems.com',
    author='Jason Woodward',
    author_email='woodwardj@averesystems.com',
    license='Apache License, Version 2.0',
    install_requires = ['boto', 'oauth2client', 'google-api-python-client', 'requests>=2.8.0'],
    packages=['vFXT'],
    test_suite="tests",
    scripts=['vfxt.py'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
    ],
)
