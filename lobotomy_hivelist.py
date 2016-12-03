__author__ = 'w2k8, iScripters'

import sys
import commands
import main
import MySQLdb

Lobotomy = main.Lobotomy()
plugin = "hivelist"


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)
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
    for hiveitem in data:
        if hiveitem.startswith("0x"):
            virtual, physical, hivefilepath = hiveitem.split(" ", 2)
            hivefilepath = hivefilepath.strip("\n")
            hivefilepath = Lobotomy.escchar(hivefilepath)
            SQL_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}')".format(plugin, virtual, physical, hivefilepath)
            Lobotomy.exec_sql_query(SQL_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
