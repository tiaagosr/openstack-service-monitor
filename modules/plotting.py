import matplotlib.pyplot as plt
from cycler import cycler
from functools import reduce
from modules.definitions import PcapAnalysisModule
from modules.link_metering import LinkMetering, MeteringData


class DataPlotting:
    PLOT_PIE = 1
    PLOT_LINE = 0

    def __init__(self, db_path, services=list(LinkMetering.SERVICES)+['etc'], session_id=1):
        PcapAnalysisModule.init_db(db_path)
        LinkMetering.init_db(db_path)
        self.services = services
        self.session_id = session_id

    @staticmethod
    def plot_increase(pos, val):
            pos[-1] += val

    @staticmethod
    def plot_append(pos, val):
        pos.append(val)

    def metering_data(self, categorized=True):
        plot_value = {'y': []}
        if categorized:
            plot_value['services'] = {x: [] for x in self.services}
            data_func = self.process_service_data
        else:
            plot_value['ports'] = {}
            data_func = self.process_etc_data

        query = MeteringData.select().where(MeteringData.session_id == self.session_id)

        for index, row in enumerate(query):
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
        current_row_ports_index = list(map(lambda x: x['port'], row.etc_ports))
        # 0 to each absent ports
        missing_row_ports_index = [x for x in plot_value['ports'] if x not in current_row_ports_index]
        for port in missing_row_ports_index:
            row_func(plot_value['ports'][port], 0)

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

        cy = cycler('color', ['red', 'green', 'blue', 'orange', 'purple', 'turquoise', 'brown', 'grey', 'cyan'])
        ax.set_prop_cycle(cy)

        plt.title(title)
        plt.grid(True, 'major', 'y', ls='--', lw=.5, c='k', alpha=.3)

        return fig, ax

    def metering_plot(self, plot_type=PLOT_LINE, categorized=True):
        plot_data = self.metering_data(categorized=categorized)

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
        _, ax = self.format_plot(title)

        plotting_func(plot_data, data, legends, ax)

        plt.show()

    def line_setup(self, plot_data, data, legends, ax):
        for line in data:
            plt.plot(plot_data['y'], data[line])

        #xcoords = [100, 190, 280, 370, 460]
        xcoords = []
        for xc in xcoords:
            plt.axvline(x=xc, linestyle='--', alpha=0.5)

        plt.ylabel('Bandwidth (bytes)')
        plt.xlabel('Time (seconds)')

        plt.legend(legends, loc='upper left')

    def pie_setup(self, plot_data, data, legends, ax):
        sizes = []
        for line in data:
            sizes.append(reduce((lambda x, y: x + y), data[line]))
        legends = [x for index, x in enumerate(legends) if sizes[index] > 0]
        sizes = [x for x in sizes if x > 0]

        ax.pie(sizes, labels=legends, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')
