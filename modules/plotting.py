import matplotlib.pyplot as plt
from cycler import cycler
from datetime import datetime
from functools import reduce
from modules.definitions import MonitoringModule
from modules.link_metering import LinkMetering, MeteringData


class DataPlotting:
    TRAFFIC_OUTBOUND = MonitoringModule.TRAFFIC_OUTBOUND
    TRAFFIC_INBOUND = MonitoringModule.TRAFFIC_INBOUND
    PLOT_PIE = 1
    PLOT_LINE = 0

    def __init__(self, db_path, services=list(LinkMetering.SERVICES)+['etc']):
        LinkMetering.init_db(db_path, create_tables=False)
        self.date_format = '%H:%M:%S'
        self.services = services

    @staticmethod
    def plot_increase(pos, val):
            pos[-1] += val

    @staticmethod
    def plot_append(pos, val):
        pos.append(val)

    def metering_data(self, traffic_type=None, categorized=True):
        plot_value = {'y': []}
        if categorized:
            plot_value['services'] = {x: [] for x in self.services}
            data_func = self.process_service_data
        else:
            plot_value['ports'] = {}
            data_func = self.process_etc_data

        if traffic_type != None:
            query = MeteringData.select().where(MeteringData.type == traffic_type)
        else:
            query = MeteringData.select()

        for index, row in enumerate(query):
            # Every odd row sum its value to the even row before
            # Reason: each metering creates 2 rows, one for inbound traffic and one for outbound traffic
            # The sum only happens if no traffic type was defined
            if index % 2 != 0 and traffic_type is not None:
                plot_row = self.plot_increase
            # Every even row, starting from 0
            else:
                # plot_value['y'].append(datetime.strptime(row.time, self.date_format))
                plot_value['y'].append(row.time)
                plot_row = self.plot_append
            data_func(index, row, plot_value, plot_row)
        return plot_value

    def process_etc_data(self, index, row, plot_value, row_func):
        for traffic in row.etc_ports:
            if traffic['port'] not in plot_value['ports']:
                #Create new port in plotting list
                plot_value['ports'][traffic['port']] = [0] * index
            #New entry to existing port
            row_func(plot_value['ports'][traffic['port']], traffic['value'])
        current_row_ports_index = map(lambda x: x['port'], row.etc_ports)
        [row_func(plot_value['ports'][x], 0) for x in plot_value['ports'] if x not in current_row_ports_index]

    def process_service_data(self, index, row, plot_value, row_func):
        for service in plot_value['services']:
            row_func(plot_value['services'][service], getattr(row, service, 0))

    def format_plot(self, title=''):
        fig, ax = plt.subplots(1, 1, figsize=(12, 9))

        ax.spines['top'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False)

        ax.get_xaxis().tick_bottom()
        ax.get_yaxis().tick_left()

        cy = cycler('color', ['red', 'green', 'blue', 'yellow', 'orange', 'purple', 'turquoise', 'brown', 'grey', 'cyan'])
        ax.set_prop_cycle(cy)

        plt.title(title)
        plt.grid(True, 'major', 'y', ls='--', lw=.5, c='k', alpha=.3)

        return fig, ax

    def metering_plot(self, plot_type=PLOT_LINE, categorized=True, traffic_type=None):
        plot_data = self.metering_data(traffic_type=traffic_type, categorized=categorized)

        if categorized:
            data = plot_data['services']
            legends = data
        else:
            data = plot_data['ports']
            legends = list(map(lambda x: 'TCP port '+str(x), data))

        if plot_type == DataPlotting.PLOT_LINE:
            plotting_func = self.line_setup
        else:
            plotting_func = self.pie_setup

        title = 'Total Traffic'
        if traffic_type == MonitoringModule.TRAFFIC_OUTBOUND:
            title = 'Outbound Traffic'
        elif traffic_type == MonitoringModule.TRAFFIC_INBOUND:
            title = 'Inbound Traffic'
        _, ax = self.format_plot(title)

        plotting_func(plot_data, data, legends, ax)

        plt.show()

    def line_setup(self, plot_data, data, legends, ax):
        for line in data:
            plt.plot(plot_data['y'], data[line])

        plt.legend(legends, loc='upper left')

    def pie_setup(self, plot_data, data, legends, ax):
        sizes = []
        for line in data:
            sizes.append(reduce((lambda x, y: x + y), data[line]))
        legends = [x for index, x in enumerate(legends) if sizes[index] > 0]
        sizes = [x for x in sizes if x > 0]

        ax.pie(sizes, labels=legends, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')
