# Openstack service monitor
A network monitoring system developed to gather information from Management Networks in OpenStack deployments.
This software operates on the host OS of a deployed controller, accessing all the management interface traffic.

The software architecture is comprised of two modules, each one representing a functionality that may collect or process data.

## Link Metering
This module collects and stores Management Network TCP bandwith data. The traffic is classified either by service (ports aggregation) or most used ports.

## API Logging
This module logs HTTP requests to ports defined in the service monitor. The request is then mapped to a specific action by comparing the request data against several regular expression.
