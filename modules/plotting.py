import matplotlib.pyplot as plt
from cycler import cycler
import numpy as np
from datetime import datetime
from database import DBSession

class DataPlotting():
    def __init__(self, dbpath):
        self.db = DBSession(dbpath)
        self.db.create_conn()
        self.color_seq = ['#1f77b4', '#aec7e8', '#ff7f0e', '#ffbb78', '#2ca02c',
                  '#98df8a', '#d62728', '#ff9896', '#9467bd', '#c5b0d5',
                  '#8c564b', '#c49c94', '#e377c2', '#f7b6d2', '#7f7f7f',
                  '#c7c7c7', '#bcbd22', '#dbdb8d', '#17becf', '#9edae5']
        self.date_format = '%Y-%m-%d %H:%M:%S'
        self.services = ['cinder', 'etc', 'glance', 'keystone', 'nova', 'swift']
    
    def get_db_data(self):
        db_data = self.db.wrap_access(self._db_link_metering_data)
        plot_value = {
            'y': [],
            'cinder': [],
            'etc': [],
            'glance': [],
            'keystone': [],
            'nova': [],
            'swift': []
        }

        for row in db_data:
            plot_value['cinder'].append(row[0])
            plot_value['etc'].append(row[1])
            plot_value['glance'].append(row[2])
            plot_value['keystone'].append(row[3])
            plot_value['nova'].append(row[4])
            plot_value['swift'].append(row[5])
            plot_value['y'].append(datetime.strptime(row[6], self.date_format))

        return plot_value

    def gen_link_metering_plot(self):
        plot_data = self.get_db_data()

        fig, ax = plt.subplots(1, 1, figsize=(12, 9))

        ax.spines['top'].set_visible(False)
        ax.spines['bottom'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_visible(False)

        ax.get_xaxis().tick_bottom()
        ax.get_yaxis().tick_left()

        cy = cycler('color', ['red', 'green', 'blue', 'yellow', 'orange', 'purple'])
        ax.set_prop_cycle(cy)

        plt.plot(plot_data['y'], plot_data['cinder'], label='cinder')
        plt.plot(plot_data['y'], plot_data['etc'], label='etc')
        plt.plot(plot_data['y'], plot_data['glance'], label='glance')
        plt.plot(plot_data['y'], plot_data['keystone'], label='keystone')
        plt.plot(plot_data['y'], plot_data['nova'], label='nova')
        plt.plot(plot_data['y'], plot_data['swift'], label='swift')

        plt.legend(self.services, loc='upper left')


        plt.grid(True, 'major', 'y', ls='--', lw=.5, c='k', alpha=.3)

        plt.show()



    def _db_link_metering_data(self, cursor):
        cursor.execute('SELECT m_cinder, m_etc, m_glance, m_keystone, m_nova, m_swift, time FROM link_usage ORDER BY id')
        return cursor.fetchall()