# Copyright (c) 2015-2017 Avere Systems, Inc.  All Rights Reserved.
from setuptools import setup

version = {}
with open("vFXT/version.py") as f:
    exec(f.read(), version)

setup(name='vFXT',
  version=version['__version__'],
  description='vFXT interaction library',
  url='http://www.averesystems.com',
  author='Jason Woodward',
  author_email='woodwardj@averesystems.com',
  license='Proprietary',
  install_requires = ['boto', 'oauth2client', 'google-api-python-client', 'requests>=2.8.0'],
  packages=['vFXT'],
  test_suite="tests",
  scripts=['vfxt.py'],
)
