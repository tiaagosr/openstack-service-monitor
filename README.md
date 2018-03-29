# openstack-service-monitor
A network monitoring system developed to gather information from Management Networks in OpenStack deployments.
This software operates on the host OS of a deployed controller, accessing all the management interface traffic.

The software architecture is comprised of several modules, each one representing a functionality that may collect or process data.

## Link Metering
This module collects and stores Management Network TCP bandwith data. The traffic is classified either by service (ports aggregation) or most used ports.
