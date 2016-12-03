__author__ = 'w2k8, iScripters'

# 11 aug 2015:      w2k8
# Plugin:           hashdump


import sys
import main
import commands
Lobotomy = main.Lobotomy()
plugin = "hashdump"

DEBUG = False


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
    items = log.split('\n')

    for line in items:
        if not line.startswith('ERROR   : volatility.plugins.registry.lsadump'):
            sql_line = "INSERT INTO {} VALUES (0, ".format(plugin)
            if not line.startswith('Volatility Foundation Volatility Framework'):
                resultline = line.split(':')
                sql_line = sql_line + "'{}',".format(line)
                for result in resultline:
                    if result != "":
                        sql_line = sql_line + "'{}',".format(result)
                sql_line = sql_line[:-1] + ")"
                try:
                    Lobotomy.exec_sql_query(sql_line, database)
                except:
                    pass
        if line.startswith('ERROR   : volatility.plugins.registry.lsadump'):
            sql_line = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}')".format(plugin, line, '0', '0', '0', '0')
            Lobotomy.exec_sql_query(sql_line, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
