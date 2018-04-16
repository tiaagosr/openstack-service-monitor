import imports
import argparse

from modules.definitions import MonitoringModule
from modules.link_metering import LinkMetering
#from modules.api_logging import ApiLogging
from modules.plotting import DataPlotting
from modules.simple_scenario import ScenarioManager

db_file = 'monitoring.db'

services = list(LinkMetering.MAP.keys())

parser = argparse.ArgumentParser(description='OpenStack Service Monitoring System')
subparser = parser.add_subparsers(title='Modules', dest='module')

monitor = subparser.add_parser('monitor', help='Execute monitoring modules')
mode_map = {'IPv4': MonitoringModule.MODE_IPV4, 'IPv6': MonitoringModule.MODE_IPV6}
monitor.add_argument('-m', '--modules', nargs='+', dest='monitors', help='Select modules to execute\nbandwidth: Monitor control network bandwidth usage\napi: Log api calls', type=str, choices=['bandwidth', 'api'], default=['bandwidth'])
monitor.add_argument('-i', '--interface', action='store', dest='iface', help='Interface monitored (Control Network) by monitoring modules', type=str, default='lo')
monitor.add_argument('-im', '--ip_mode', action='store', dest='ip_mode', help='IP Mode: IPv4, IPv6', type=str, default='IPv4', choices=mode_map, metavar='IP_MODE')


bandwidth = monitor.add_argument_group('Bandwidth')
bandwidth.add_argument('-t', '--interval', action='store', dest='interval', help='Monitored bandwidth logging interval', type=int, default=5)
bandwidth.add_argument('-w', '--write-pcap', action='store', dest='pcap', help='Path to output pcap file', type=str, default='')

api_log = monitor.add_argument_group('Api logging')

scenario = monitor.add_argument_group('Scenario')
scenario.add_argument('-sc', '--execute-scenario', action='store_true', dest='use_scenario', help='Execute simple use scenario during monitoring')
scenario.add_argument('-vm', '--vm-count', action='store', dest='vm_count', help='Number of vms instance created through the scenario execution', type=int, default=1)
scenario.add_argument('-sl', '--state-list', action='store', dest='state_list', help='Ordered state list which vm instances will cycle through the scenarion execution', nargs="+", choices=['suspend', 'resume', 'reboot', 'shelve', 'stop'], default=['suspend', 'resume', 'stop', 'shelve'], metavar='\b')


plot = subparser.add_parser('plot',  help='Plot control network traffic data')
category_map = {'categorized': True, 'uncategorized': False}
plot_map = {'pie': DataPlotting.PLOT_PIE, 'line': DataPlotting.PLOT_LINE}
direction_map = {'inbound': LinkMetering.TRAFFIC_INBOUND, 'outbound': LinkMetering.TRAFFIC_OUTBOUND, 'both': None}
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
    def metering_plot(plot_type=DataPlotting.PLOT_PIE, categorized=True, traffic_type=None, services=None, pcap=None):
        plot = DataPlotting(db_file, services=services)
        plot.metering_plot(plot_type=plot_type, categorized=categorized, traffic_type=traffic_type)

    @staticmethod
    def apply_scenario(vm_count, state_list):
        scenario = ScenarioManager()
        scenario.authenticate()
        scenario.network_cfg()

        scenario.test_scenario(vm_count, state_list)


if __name__ == '__main__':
    args = parser.parse_args()
    if args.module == 'monitor':
        monitor_bandwidth = None
        ip_mode = mode_map[args.ip_mode[0]]
        #Monitoring Modules
        if 'bandwidth' in args.monitors:
            pcap_file = args.pcap if args.pcap != '' else None
            monitor_bandwidth = UseCase.monitor_link(iface=args.iface, interval=args.interval, mode=ip_mode, pcap=pcap_file)
        if 'api' in args.monitors:
            raise NotImplementedError("Api logging to be implemented!")
        #Scenario
        if args.use_scenario:
            UseCase.apply_scenario(args.vm_count, args.state_list)
            if monitor_bandwidth is not None:
                monitor_bandwidth.stop_execution()
    elif args.module == 'plot':
        categorized = category_map[args.data_type]
        traffic = direction_map[args.traffic_direction]
        type = plot_map[args.plot_type]
        UseCase.metering_plot(plot_type=type, categorized=categorized, traffic_type=traffic, services=args.service_list)
