__author__ = 'w2k8'

import sys
import commands
import main

Lobotomy = main.Lobotomy()
plugin = "autoruns"


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py --plugins={} -f {} --profile={} {}'.format(plugin_dir, imagename, imagetype, plugin)
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
    autorun = ''
    counter = 0
    tmp = []
    write_sql = []

    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework'):
            line = line.strip('\n')
            if line.endswith('====================================='):
                counter += 1
                autorun = line.strip('=')
            else:
                if counter == 0:
                    # Put every line in a list
                    if line != '':
                        tmp.append(line)
                    else:
                        write_sql.append([autorun, tmp])
                        tmp = []
                else:
                    counter = 0

    for autoruntype, line in write_sql:
        autorun = ''
        for item in line:
            item = Lobotomy.escchar(item)
            # item = item.replace('\\', '\\\\')
            if item != '':
                autorun += item + '\n'
        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}')".format(plugin, autoruntype, autorun)
        Lobotomy.exec_sql_query(sql_cmd, database)
    return


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])




