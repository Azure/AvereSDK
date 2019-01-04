# Copyright (c) 2015-2019 Avere Systems, Inc.  All Rights Reserved.
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the project root for license information.
'''Abstraction for backend services instance objects

Because the data structure/objects backend services consume and return are not
uniform, ServiceInstance abstracts them and provides a useful and consistent
interface.

Cookbook/examples:

# AWS existing
inst = ServiceInstance(service=aws, instance_id='i-83739423')
# AWS new
i = aws.create_instance(...)
inst = ServiceInstance(aws, i)

# GCE existing
inst = ServiceInstance(service=gce, instance_id='my-node-1')
# GCE new
i = gce.create_instance(...)
inst = ServiceInstance(gce, i)

# or the .create() constructor which takes
srv = aws or gce or azure
inst = ServiceInstance.create(srv, **opts)

# using the ServiceInstance

inst.start()
inst.stop()
inst.restart()
inst.destroy()
inst.shelve()
inst.unshelve()

inst.is_on()
inst.is_off()
inst.is_shelved()

inst.id()
inst.name()
inst.ip()
inst.fqdn()
inst.status()

inst.refresh()

inst.in_use_addresses()
inst.add_address('172.16.16.20')
inst.remove_address('172.16.16.20')
'''

from vFXT.service import *

class ServiceInstance(object):
    '''Presents service specific instance objects in a general way.  This may
        or may not be a vFXT (and so is usable for general purpose cloud instances)

        The ServiceInstance composes both the backend service object and the
        instance object that is returned from the backend service.  Every
        method delegates to the service interface.
    '''
    def __init__(self, service=None, instance_id=None, instance=None):
        '''Constructor

            Arguments:
                service (Service object): backend service
                instance_id (str, optional): instance ID
                instance (obj, optional): instance object as returned from the backend

            Either an instance ID or an instance must be provided.  If the
            instance ID is provided, the instance object is looked up from
            the backend.
        '''
        self.instance_id    = instance_id
        self.instance       = instance
        self.service        = service
        if instance_id and service and not instance:
            self.instance = service.get_instance(instance_id)
            if not self.instance:
                raise vFXTConfigurationException("No such instance: {}".format(instance_id))
        if instance and service and not instance_id:
            self.instance_id = service.instance_id(self.instance)

        if not self.instance:
            raise vFXTConfigurationException("An instance ID or instance object must be provided")

    @classmethod
    def create(cls, service, *args, **kwargs):
        '''Create an instance

            This delegates to the service.create_instance call.  See
            documentation there for specific arguments supported by the
            backend service.
        '''
        instance = service.create_instance(*args, **kwargs)
        return cls(service, instance=instance)

    # delegate to service

    def can_stop(self):
        '''Some instance configurations cannot be stopped. Check if this is one.'''
        return self.service.can_stop(self.instance)

    def stop(self):
        '''Stop the instance'''
        self.service.stop(self.instance)
        self.refresh()

    def start(self):
        '''Start the instance'''
        self.service.start(self.instance)
        self.refresh()

    def restart(self):
        '''Restart the instance'''
        self.service.restart(self.instance)
        self.refresh()

    def destroy(self, **options):
        '''Destroy the instance'''
        self.refresh()
        return self.service.destroy(self.instance, **options)

    def is_on(self):
        '''Return True if the instance is currently on'''
        return self.service.is_on(self.instance)

    def is_off(self):
        '''Return True if the instance is currently off'''
        return self.service.is_off(self.instance)

    def is_shelved(self):
        '''Return True if the instance is currently shelved'''
        return self.service.is_shelved(self.instance)

    def id(self):
        '''The instance ID'''
        return self.instance_id

    def name(self):
        '''The instance name'''
        return self.service.name(self.instance)

    def ip(self):
        '''The primary IP address of the instance'''
        return self.service.ip(self.instance)

    def fqdn(self):
        '''The instance fully qualified domain name'''
        return self.service.fqdn(self.instance)

    def status(self):
        '''The instance status (str)'''
        return self.service.status(self.instance)

    def refresh(self):
        '''Refresh the backend instance object'''
        self.instance = self.service.refresh(self.instance)
        if not self.instance:
            raise vFXTConfigurationException("Failed to refresh, no such instance: {}".format(self.instance_id))

    def can_shelve(self):
        '''Some instance configurations cannot be shelved. Check if this is one.'''
        return self.service.can_shelve(self.instance)

    def shelve(self):
        '''Shelve the instance'''
        self.refresh()
        self.service.shelve(self.instance)
        self.refresh()

    def unshelve(self, **options):
        '''Unshelve the instance'''
        self.refresh()
        self.service.unshelve(self.instance, **options)
        self.refresh()

    def wait_for_service_checks(self):
        '''Wait for any instance service checks (if available)'''
        return self.service.wait_for_service_checks(self.instance)

    def in_use_addresses(self, category='all'):
        '''Get the in use addresses for the instance

            Arguments:
                category (str): all (default), instance, routes
        '''
        self.refresh()
        return self.service.instance_in_use_addresses(self.instance, category)

    def add_address(self, address, **options):
        '''Add an address to the instance

            Arguments:
                address (str): IP address
                options (dict): passed to service backend
        '''
        self.refresh()
        self.service.add_instance_address(self.instance, address, **options)
        self.refresh()

    def remove_address(self, address):
        '''Remove an address from the instance

            Arguments:
                address (str): IP address
        '''
        self.refresh()
        self.service.remove_instance_address(self.instance, address)
        self.refresh()
