import imports
import argparse
import time

from modules.api_logging import ApiLogging
from modules.definitions import PcapAnalysisModule
from modules.link_metering import LinkMetering
from modules.plotting import DataPlotting
from modules.simple_scenario import ScenarioManager
import subprocess as sub

db_file = 'monitoring.db'

services = list(LinkMetering.MAP.keys())

parser = argparse.ArgumentParser(description='OpenStack Service Monitoring System')
subparser = parser.add_subparsers(title='Modules', dest='module')

monitor = subparser.add_parser('monitor', help='Create data dump with tcpdump')
monitor.add_argument('-i', '--interface', action='store', dest='iface', help='Interface monitored (Control Network) by monitoring modules', type=str, default='lo')
monitor.add_argument('-o', '--output', action='store', dest='pcap', help='output capture file name', type=str, default=None)


analysis = subparser.add_parser('analysis', help='Execute pcap analysis modules')
analysis.add_argument('-i', '--interface', action='store', dest='iface', help='Interface whose data is stored in the pcap src file', type=str, default='lo')
analysis.add_argument('-m', '--modules', nargs='+', dest='monitors', help='Select modules to execute\nbandwidth: Analyze control network bandwidth usage\napi: Log api calls', type=str, choices=['bandwidth', 'api'], default=['bandwidth'])
analysis.add_argument('-p', '--pcap', action='store', dest='pcap', help='Pcap src file used by all analysis modules', type=str, default='monitored.pcap')

bandwidth = analysis.add_argument_group('Bandwidth')
bandwidth.add_argument('-bp', '--bandwidth-pcap', action='store', dest='pcap_b', help='Bandwidth analysis pcap src file', type=str, default='')

api_log = analysis.add_argument_group('Api logging')
api_log.add_argument('-ap', '--api-pcap', action='store', dest='pcap_a', help='API logging pcap src file', type=str, default='')


scenario = monitor.add_argument_group('Scenario')
scenario.add_argument('-sc', '--execute-scenario', action='store_true', dest='use_scenario', help='Execute simple use scenario during monitoring')
scenario.add_argument('-vm', '--vm-count', action='store', dest='vm_count', help='Number of VMs instance created through the scenario execution', type=int, default=1)
scenario.add_argument('-sl', '--state-list', action='store', dest='state_list', help='Ordered state list which VM instances will cycle through the scenarion execution', nargs="+", choices=['suspend', 'resume', 'reboot', 'shelve', 'stop'], default=['suspend', 'resume', 'stop', 'shelve'], metavar='\b')
scenario.add_argument('-vf', '--vm-flavor', action='store', dest='vm_flavor', help='Flavor which the Vms instance will use', type=str, default='m1.small')
scenario.add_argument('-vi', '--vm-image', action='store', dest='vm_image', help='Image which the Vms instance will use', type=str, default='trusty-server')


plot = subparser.add_parser('plot',  help='Plot control network traffic data')
category_map = {'categorized': True, 'uncategorized': False}
plot_map = {'pie': DataPlotting.PLOT_PIE, 'line': DataPlotting.PLOT_LINE}
plot.add_argument('-id', '--session-id', action='store', dest='session_id', help='Monitorated data session id', type=int, default=1)
plot.add_argument('-p', '--plot-type', action='store', dest='plot_type', help='Plot type', type=str, choices=['pie', 'line'], default='line')
plot.add_argument('-t', '--data-type', action='store', dest='data_type', help='Plotted data type', type=str, choices=category_map, default='categorized')
plot.add_argument('-s', '--services', dest='service_list', help='Services to be displayed in categorized plot', nargs='+', type=str, choices=services+['etc', 'total'], default=services+['etc'], metavar='\b')

class UseCase:
    @staticmethod
    def analyze_link(db_path=db_file, **kwargs):
        link_metering = LinkMetering(db_path=db_path, **kwargs)
        link_metering.start_analysis()
        return link_metering

    @staticmethod
    def metering_plot(plot_type=DataPlotting.PLOT_PIE, categorized=True, services=None, session_id=1):
        plot = DataPlotting(db_file, services=services, session_id=session_id)
        plot.metering_plot(plot_type=plot_type, categorized=categorized)

    @staticmethod
    def log_api(db_path=db_file, **kwargs):
        api_logging = ApiLogging(db_path=db_path, **kwargs)
        api_logging.start()
        return api_logging

    @staticmethod
    def init_scenario(**kwargs):
        test_scenario = ScenarioManager(**kwargs)
        test_scenario.authenticate()
        test_scenario.network_cfg()
        return test_scenario

    @staticmethod
    def start_scenario(scenario, vm_count, state_list):
        #Start scenario when t=5
        while PcapAnalysisModule.execution_time() < 5:
            time.sleep(0.1)

        scenario.test_scenario(vm_count, state_list)


if __name__ == '__main__':
    args = parser.parse_args()
    if args.module == 'monitor':
        tcpdump = None
        tcpdump_all = None
        test_scenario = None
        if args.pcap is not None:
            pcap_path = args.pcap+'.pcap'
            tcpdump = sub.Popen('exec tcpdump -w '+pcap_path+' -i '+args.iface, shell=True, stdout=sub.DEVNULL)
        if args.use_scenario:
            test_scenario = UseCase.init_scenario(image=args.vm_image, flavor=args.vm_flavor)
        else:
            current_time = PcapAnalysisModule.execution_time
            targeted_time = 610
            while current_time() < targeted_time:
                time.sleep(0.1)
        #Scenario
        if test_scenario is not None:
            UseCase.start_scenario(test_scenario, args.vm_count, args.state_list)
            print('Finished scenario at time: ', PcapAnalysisModule.execution_time())
        if tcpdump is not None:
            tcpdump.terminate()
            tcpdump.wait()
            print('Finished monitoring at time: ', PcapAnalysisModule.execution_time())

    if args.module == 'analysis':
        session = PcapAnalysisModule.create_session(args.iface, db_file)
        api_log = None
        monitor_bandwidth = None
        #Analysis Modules
        if 'bandwidth' in args.monitors:
            pcap_path = args.pcap_b if args.pcap_b != '' else args.pcap
            monitor_bandwidth = UseCase.analyze_link(pcap=pcap_path, session=session)
        if 'api' in args.monitors:
            pcap_path = args.pcap_a if args.pcap_a != '' else args.pcap
            api_log = UseCase.log_api(pcap=pcap_path, session=session)
        if monitor_bandwidth is not None:
            monitor_bandwidth.join()
        if api_log is not None:
            api_log.join()

    elif args.module == 'plot':
        categorized = category_map[args.data_type]
        type = plot_map[args.plot_type]
        UseCase.metering_plot(plot_type=type, categorized=categorized, services=args.service_list, session_id=args.session_id)
