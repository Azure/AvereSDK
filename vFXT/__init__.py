# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
'''Avere virtual FXT (vFXT) library'''

from .version import __version__, __version_info__
from .cluster import Cluster
from .serviceInstance import ServiceInstance
from .cidr import Cidr
from .service import ServiceBase
