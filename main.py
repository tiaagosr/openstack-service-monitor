import imports
import argparse
from modules.link_metering import LinkMetering
#from modules.api_logging import ApiLogging
from modules.plotting import DataPlotting
from modules.simple_scenario import ScenarioManager

current_interface = 'enp0s20u3'
current_interface = 'wlp2s0'
db_file = 'monitoring.db'


class UseCase:
    @staticmethod
    def monitor_link(iface=current_interface, db_path=db_file, interval=5):
        link_metering = LinkMetering(iface=iface, db_path=db_path, interval=interval)
        link_metering.start_monitoring()

    @staticmethod
    def metering_plot(plot_type=DataPlotting.PLOT_PIE, categorized=True, traffic_type=None):
        plot = DataPlotting(db_file)
        plot.metering_plot(plot_type=plot_type, categorized=categorized, traffic_type=traffic_type)

    @staticmethod
    def apply_scenario(vm_count=2, state_list=['suspend', 'resume', 'stop', 'shelve']):
        scenario = ScenarioManager()
        scenario.authenticate()
        scenario.network_cfg()

        scenario.test_scenario(vm_count, state_list)

if __name__ == '__main__':
