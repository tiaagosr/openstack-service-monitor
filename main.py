import time

import imports
import argparse

from modules.api_logging import ApiLogging
from modules.definitions import MonitoringModule
from modules.link_metering import LinkMetering
from modules.plotting import DataPlotting
from modules.simple_scenario import ScenarioManager
import subprocess as sub

db_file = 'monitoring.db'

services = list(LinkMetering.MAP.keys())

parser = argparse.ArgumentParser(description='OpenStack Service Monitoring System')
subparser = parser.add_subparsers(title='Modules', dest='module')

monitor = subparser.add_parser('monitor', help='Execute monitoring modules')
mode_map = {'IPv4': MonitoringModule.MODE_IPV4, 'IPv6': MonitoringModule.MODE_IPV6}
monitor.add_argument('-m', '--modules', nargs='+', dest='monitors', help='Select modules to execute\nbandwidth: Monitor control network bandwidth usage\napi: Log api calls', type=str, choices=['bandwidth', 'api', 'tcpdump'], default=['bandwidth'])
monitor.add_argument('-i', '--interface', action='store', dest='iface', help='Interface monitored (Control Network) by monitoring modules', type=str, default='lo')
monitor.add_argument('-im', '--ip_mode', action='store', dest='ip_mode', help='IP Mode: IPv4, IPv6', type=str, default='IPv4', choices=mode_map, metavar='IP_MODE')


bandwidth = monitor.add_argument_group('Bandwidth')
bandwidth.add_argument('-t', '--interval', action='store', dest='interval', help='Monitored bandwidth logging interval', type=int, default=5)
bandwidth.add_argument('-w', '--write-pcap', action='store', dest='pcap', help='Path to output pcap file', type=str, default='')

api_log = monitor.add_argument_group('Api logging')

scenario = monitor.add_argument_group('Scenario')
scenario.add_argument('-sc', '--execute-scenario', action='store_true', dest='use_scenario', help='Execute simple use scenario during monitoring')
scenario.add_argument('-vm', '--vm-count', action='store', dest='vm_count', help='Number of VMs instance created through the scenario execution', type=int, default=1)
scenario.add_argument('-sl', '--state-list', action='store', dest='state_list', help='Ordered state list which VM instances will cycle through the scenarion execution', nargs="+", choices=['suspend', 'resume', 'reboot', 'shelve', 'stop', 'shelve_offload'], default=['suspend', 'resume', 'stop', 'shelve', 'shelve_offload'], metavar='\b')
monitor.add_argument('-vf', '--vm-flavor', action='store', dest='vm_flavor', help='Flavor which the Vms instance will use', type=str, default='m1.small')
monitor.add_argument('-vi', '--vm-image', action='store', dest='vm_image', help='Image which the Vms instance will use', type=str, default='trusty-server')


plot = subparser.add_parser('plot',  help='Plot control network traffic data')
category_map = {'categorized': True, 'uncategorized': False}
plot_map = {'pie': DataPlotting.PLOT_PIE, 'line': DataPlotting.PLOT_LINE}
direction_map = {'inbound': LinkMetering.TRAFFIC_INBOUND, 'outbound': LinkMetering.TRAFFIC_OUTBOUND, 'both': None}
scenario.add_argument('-id', '--session-id', action='store', dest='session_id', help='Monitorated data session id', type=int, default=1)
plot.add_argument('-p', '--plot-type', action='store', dest='plot_type', help='Plot type', type=str, choices=['pie', 'line'], default='line')
plot.add_argument('-t', '--data-type', action='store', dest='data_type', help='Plotted data type', type=str, choices=category_map, default='categorized')
plot.add_argument('-s', '--services', dest='service_list', help='Services to be displayed in categorized plot', nargs='+', type=str, choices=services+['etc'], default=services+['etc'], metavar='\b')
plot.add_argument('-d', '--direction', action='store', dest='traffic_direction', help='Network traffic direction', type=str, choices=direction_map, default='both')


class UseCase:
    @staticmethod
    def monitor_link(db_path=db_file, **kwargs):
        link_metering = LinkMetering(db_path=db_path, **kwargs)
        link_metering.start_monitoring()
        return link_metering

    @staticmethod
    def metering_plot(plot_type=DataPlotting.PLOT_PIE, categorized=True, traffic_type=None, services=None):
        plot = DataPlotting(db_file, services=services)
        plot.metering_plot(plot_type=plot_type, categorized=categorized, traffic_type=traffic_type)

    @staticmethod
    def log_api(db_path=db_file, **kwargs):
        api_logging = ApiLogging(db_path=db_path, **kwargs)
        api_logging.start_monitoring()
        return api_logging

    @staticmethod
    def init_scenario(**kwargs):
        test_scenario = ScenarioManager(**kwargs)
        test_scenario.authenticate()
        test_scenario.network_cfg()
        return test_scenario

    @staticmethod
    def start_scenario(scenario, vm_count, state_list):
        scenario.test_scenario(vm_count, state_list)


if __name__ == '__main__':
    args = parser.parse_args()
    if args.module == 'monitor':
        monitor_bandwidth = None
        api_log = None
        tcpdump = None
        test_scenario = None
        ip_mode = mode_map[args.ip_mode]
        session = MonitoringModule.create_session(args.iface, db_file)
        if args.use_scenario:
            test_scenario = UseCase.init_scenario(image=args.vm_image, flavor=args.vm_flavor)
        #Monitoring Modules
        if 'tcpdump' in args.monitors:
            pcap_file = args.pcap if args.pcap != '' else 'tcpdump.pcap'
            tcpdump = sub.Popen('exec tcpdump -w '+pcap_file+' -i '+args.iface, shell=True, stdout=sub.DEVNULL)
        if 'bandwidth' in args.monitors:
            pcap_file = args.pcap if args.pcap != '' else None
            monitor_bandwidth = UseCase.monitor_link(interface=args.iface, interval=args.interval, mode=ip_mode, pcap=pcap_file, session=session)
        if 'api' in args.monitors:
            api_log = UseCase.log_api(interface=args.iface, mode=ip_mode, session=session)
        #Scenario
        if test_scenario is not None:
            UseCase.start_scenario(test_scenario, args.vm_count, args.state_list)
            if monitor_bandwidth is not None:
                monitor_bandwidth.stop()
            if api_log is not None:
                api_log.stop()
            if tcpdump is not None:
                tcpdump.kill()
    elif args.module == 'plot':
        categorized = category_map[args.data_type]
        traffic = direction_map[args.traffic_direction]
        type = plot_map[args.plot_type]
        UseCase.metering_plot(plot_type=type, categorized=categorized, traffic_type=traffic, services=args.service_list, session_id=args.session_id)
