__author__ = 'w2k8'
#
# 04 jun 2016:      w2k8
# Plugin:           Mimikatz
# Detail:           Get the users and where possible the passwords from a memorydump
#                   Plugin is testen on Windows XP Stuxnet. (Zero output, no errors)
#                   Plugin is testen on Windows 7 SP1 X64. (with output, no errors)
#
# Date:             08 aug 2016
# Edited:           w2k8
# Detail:           Moved common routines to main.py
#                   Plugin cleanup
#

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "mimikatz"

DEBUG = False


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

    column = []
    data = 0
    write_sql = []

    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework'):
            tmp = line.split(' ')
            if line.startswith('----'):
                for l in range(len(tmp)):
                    column.append(len(tmp[l]))
                    data = 1
            if data == 1 and not line.startswith('---'):
                module = line[0:column[0]].strip()
                user = line[column[0] + 1:column[0] + column[1] + 1].strip()
                domain = line[column[0] + column[1] + 2:+ column[0] + column[1] + column[2] + 2].strip()
                password = line[column[0] + column[1] + column[2] + 3:].strip()
                write_sql.append([module, user, domain, password])

    for module, user, domain, password in write_sql:

        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}')".format(plugin, module, user, domain, password)
        Lobotomy.exec_sql_query(sql_cmd, database)
    return


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
