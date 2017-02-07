__author__ = 'w2k8, iScripters'
# Date:             24 jul 2016
# Edited:           w2k8
# Detail:           Created new plugin for lobotomy
#

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "iehistory"


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py -f {} --profile={} {} --output=greptext'.format(imagename, imagetype, plugin)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))

    vollog = commands.getoutput(command)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(vollog, database)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_voldata(log, database):
    data = log.split('\n')
    sql_data = []
    lp = []
    for line in data:

        if line.startswith('-----'):
            for item in line.split():
                lp.append(int(len(item) + 1))

        if not line.startswith("Process") and not line.startswith('Volatility Foundation Volatility')\
                and not line.startswith('---') and not line.startswith('****'):
            line = line.strip("\n")
            line = Lobotomy.escchar(line)

            # Volatility Version 2.5
            # if volver == '2.5':
            if line.startswith('>|'):
                tmp, Process, PID, CacheType, Offset, RecordLength, Location, LastModified, LastAccessed, Length,\
                FileOffset, DataOffset, DataSize, File, Data = line.split('|')
                sql_data.append((Process, PID, CacheType, Offset, RecordLength, Location, LastModified,
                                 LastAccessed, Length, FileOffset, DataOffset, DataSize, File, Data))

    sql_prefix = "INSERT INTO {} VALUES (0".format(plugin)

    for sql_line in sql_data:
        sql_cmd = ''
        for item in sql_line:
            # sql_line[6] and [7] are datetime formats.
            if item == sql_line[6]:
                item = Lobotomy.tz_data(database, plugin, sql_line[6])
            if item == sql_line[7]:
                item = Lobotomy.tz_data(database, plugin, sql_line[7])
            sql_cmd += ",'{}'".format(item)

        sql_cmd = '{}{})'.format(sql_prefix, sql_cmd)
        Lobotomy.exec_sql_query(sql_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
