__author__ = 'w2k8, iScripters'
#
# Script version    0.5
# Plugin version:   2
# 11 aug 2015:      W2k8
# Plugin:           memmap
# Edit:             04 okt 2016
#                   Parse the volatility memmap to map the virtual offset with the physical offset


import sys
import commands
import main
import multiprocessing
from ctypes import c_int
from multiprocessing import Value, Lock, TimeoutError
import subprocess as sub
import threading

Lobotomy = main.Lobotomy()
plugin = "memmap"


def start(databasename):
    global database
    database = databasename
    global jobscounter
    global cpucount
    jobs = []
    name = ''
    pid = ''
    virtual = ''
    physical = ''
    size = ''
    dumpfileoffset = ''
    mm1 = mm2 = mm3 = mm4 = ''
    count = 0

    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)
    # command = 'head ../dumps/03T9R6TUBFBW/stuxnet.vmem-memmap.txt'
    # command = 'cat ../dumps/03T9R6TUBFBW/stuxnet.vmem-memmap.txt'
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))
    vollog = commands.getoutput(command)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    for line in vollog.split('\n'):
        if not line.startswith('Volatility'):
            if 'pid:' in line:
                pid = line.split(' ')[-1]
                name = line.split(' ')[0]

            if not line.startswith('Virtual') and not line.startswith('---') and not line.startswith('******'):
                if pid != '':
                    counter = 0

                    for data in line.split(' '):
                        if data.startswith('0x'):
                            if counter == 0:
                                mm1 = data
                            if counter == 1:
                                mm2 = data
                            if counter == 2:
                                mm3 = data
                            if counter == 3:
                                mm4 = data
                                jobs.append((
                                             '{}'.format(pid),
                                             '{}'.format(name),
                                             '{}'.format(mm1),
                                             '{}'.format(mm2),
                                             '{}'.format(mm3),
                                             '{}'.format(mm4)
                                             ))
                                if len(jobs) == 10000:
                                    save_sql(jobs, plugin, database)
                                    jobs = []
                                    Lobotomy.pl('Plugin: {}, Database: {}, Pid: {}, name: {}, rows processed: {}'.
                                                format(plugin, database, pid, name, count))

                            counter += 1
                    count += 1

    save_sql(jobs, plugin, database)
    jobs = []
    Lobotomy.pl('Plugin: {}, Database: {}, Pid: {}, name: {}, rows processed: {}'.
                format(plugin, database, pid, name, count))

    Lobotomy.register_plugin('stop', database, plugin)


def save_sql(data, plugin, database):
    SQL_cmd = 'INSERT INTO {} (pid, name, virtual, physical, size, dumpfileoffset) values'.format(plugin)
    SQL_cmd += str(data).strip('[]')
    Lobotomy.exec_sql_query(SQL_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
