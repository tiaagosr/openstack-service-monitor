import imports
import argparse

from modules.definitions import MonitoringModule
from modules.link_metering import LinkMetering
#from modules.api_logging import ApiLogging
from modules.plotting import DataPlotting
from modules.simple_scenario import ScenarioManager

current_interface = 'enp0s20u3'
current_interface = 'wlp2s0'
db_file = 'monitoring.db'

services = list(LinkMetering.MAP.keys())

parser = argparse.ArgumentParser(description='OpenStack Service Monitoring System')
subparser = parser.add_subparsers(title='Modules', dest='module')

monitor = subparser.add_parser('monitor', help='Execute monitoring modules')
mode_map = {'IPv4': MonitoringModule.MODE_IPV4, 'IPv6': MonitoringModule.MODE_IPV6}
monitor.add_argument('-m', '--modules', nargs='+', dest='monitors', help='Select modules to execute\nbandwidth: Monitor control network bandwidth usage\napi: Log api calls', type=str, choices=['bandwidth', 'api'], default=['bandwidth'])
monitor.add_argument('-i', '--interface', dest='iface', help='Interface monitored (Control Network) by monitoring modules', type=str, nargs=1, default=current_interface)
monitor.add_argument('-im', '--ip_mode', dest='ip_mode', help='IP Mode: IPv4, IPv6', type=str, nargs=1, default='IPv4', choices=mode_map, metavar='IP_MODE')


bandwidth = monitor.add_argument_group('Bandwidth')
bandwidth.add_argument('-t', '--interval', dest='interval', help='Monitored bandwidth logging interval', type=int, nargs=1, default=5)
bandwidth.add_argument('-w', '--write-pcap', dest='pcap', help='Path to output pcap file', type=str, nargs=1, default='')

api_log = monitor.add_argument_group('Api logging')

scenario = monitor.add_argument_group('Scenario')
scenario.add_argument('-sc', '--execute-scenario', dest='use_scenario', help='Execute simple use scenario during monitoring')
scenario.add_argument('-vm', '--vm-count', dest='vm_count', help='Number of vms instance created through the scenario execution', type=int, default=1, nargs=1)
scenario.add_argument('-sl', '--state-list', dest='state_list', help='Ordered state list which vm instances will cycle through the scenarion execution', nargs="+", choices=['suspend', 'resume', 'reboot', 'shelve', 'stop'], default=['suspend', 'resume', 'stop', 'shelve'], metavar='\b')


plot = subparser.add_parser('plot',  help='Plot control network traffic data')
category_map = {'categorized': True, 'uncategorized': False}
plot_map = {'pie': DataPlotting.PLOT_PIE, 'line': DataPlotting.PLOT_LINE}
direction_map = {'inbound': LinkMetering.TRAFFIC_INBOUND, 'outbound': LinkMetering.TRAFFIC_OUTBOUND, 'both': None}
plot.add_argument('-p', '--plot-type', dest='plot_type', help='Plot type', nargs=1, type=str, choices=['pie', 'line'], default='line')
plot.add_argument('-t', '--data-type', dest='data_type', help='Plotted data type', nargs=1, type=str, choices=category_map, default='categorized')
plot.add_argument('-s', '--services', dest='service_list', help='Services to be displayed in categorized plot', nargs='+', type=str, choices=services+['etc'], default=services+['etc'], metavar='\b')
plot.add_argument('-d', '--direction', dest='traffic_direction', help='Network traffic direction', nargs=1, type=str, choices=direction_map, default='both')

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
        ip_mode = mode_map[args.ip_mode]
        #Monitoring Modules
        if 'bandwidth' in args.monitors:
            pcap_file = args.pcap[0] if args.pcap[0] != '' else None
            monitor_bandwidth = UseCase.monitor_link(iface=args.iface[0], interval=args.interval[0], mode=ip_mode, pcap=pcap_file)
        if 'api' in args.monitors:
            raise NotImplemented("Api logging to be implemented!")
        #Scenario
        if args.use_scenario:
            UseCase.apply_scenario(args.vm_count[0], args.state_list)
            if monitor_bandwidth is not None:
                monitor_bandwidth.stop_execution()
    elif args.module == 'plot':
        categorized = category_map[args.data_type[0]]
        traffic = direction_map[args.traffic_direction[0]]
        type = plot_map[args.plot_type[0]]
        UseCase.metering_plot(plot_type=type, categorized=categorized, traffic_type=traffic, services=args.service_list)
