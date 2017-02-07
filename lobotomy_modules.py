__author__ = 'w2k8, iScripters'
# Date:             24 jul 2016
# Edited:           w2k8
# Detail:           Moved plugin from multiparser to an own module
#

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "modules"


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
    for line in data:
        if not line.startswith("Offset") and not line.startswith('Volatility Foundation Volatility')\
                and not line.startswith('---'):
            line = line.strip("\n")
            line = Lobotomy.escchar(line)
            if line.startswith('>|'):
                tmp, offseta, namea, basea, sizea, filea = line.split('|')
                sql_data.append((offseta, namea, basea, sizea, filea))

    sql_prefix = "INSERT INTO {} VALUES (0".format(plugin)
    for sql_line in sql_data:
        sql_cmd = ''
        for item in sql_line:
            sql_cmd += ",'{}'".format(item)
        sql_cmd = '{}{})'.format(sql_prefix, sql_cmd)
        Lobotomy.exec_sql_query(sql_cmd, database)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
