__author__ = 'w2k8, iScripters'


import sys
import main
from cStringIO import StringIO
import commands

Lobotomy = main.Lobotomy()

plugin = "cmdline"

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

    newline = 0
    process = ''
    pid = ''
    commandline = ''

    for line in items:
        line = Lobotomy.escchar(line)
        if "pid:" in line:
            process = line.split(":")[0][:-4]
            pid = line.split(":")[1].strip(" ").strip("\n")
            newline = 1
        if line.startswith("Command line :"):
            commandline = line.split(": ", 1)[1].strip("\n")
            # commandline = commandline.replace('\\', '\\\\')
        if newline != 0 and line.startswith('*****'):
            sql_cmd = "INSERT INTO cmdline VALUES (0, '{}', '{}', '{}')".format(process, pid, commandline)

            # Build sql String

            try:
                Lobotomy.exec_sql_query(sql_cmd, database)
            except:
                print 'sql Error in ', database, 'plugin: ', plugin
                print 'sql Error: ',  sql_cmd
            newline = 0
            process = ''
            pid = ''
            commandline = ''


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])




