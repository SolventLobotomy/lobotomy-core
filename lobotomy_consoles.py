__author__ = 'w2k8, iScripters'



import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "consoles"


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
    for line in data:
        if not line.startswith("**************") and not line.startswith('Volatility Foundation Volatility'):
            line = line.strip("\n")
            line = Lobotomy.escchar(line)
            # line = line.replace('\\', '\\\\').replace("'", "\"").replace('"', '\"')
            SQL_cmd = "INSERT INTO {} VALUES (0, '{}')".format(plugin, line)
            Lobotomy.exec_sql_query(SQL_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
