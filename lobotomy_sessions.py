__author__ = 'w2k8'
#
# 11 okt 2016:      w2k8
# Plugin:           Sessions
# Detail:           Get the sessions from a memorydump

import sys
import commands
import main

Lobotomy = main.Lobotomy()
plugin = "sessions"


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
    # print items
    session= id= processes= process= process_name= process_time = PagePoolStart = PagePoolEnd = ''
    for line in items:
        # print line
        if not line.startswith('Volatility') and not line.startswith('******'):
            if line.startswith('Session'):
                tmp = line.split(' ')
                session = tmp[1]
                id = tmp[3]
                processes = tmp[5]
            if line.startswith('PagedPool'):
                tmp = line.split(' ')
                PagedPoolStart = tmp[1]
                PagedPoolEnd = tmp[3]
            if line.startswith(' Process'):
                tmp = line.split(' ', 4)
                process = tmp[2]
                process_name = tmp[3]
                process_time = tmp[4]
                sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')"\
                    .format(plugin, session, id, processes, PagedPoolStart, PagedPoolEnd,
                                    process, process_name, process_time, '', '', '')
                Lobotomy.exec_sql_query(sql_cmd, database)
            if line.startswith(' Image'):
                tmp = line.split(' ')
                image = tmp[2].strip(',')
                adress = tmp[4].strip(',')
                name = tmp[6]
                sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')"\
                    .format(plugin, session, id, processes, PagedPoolStart, PagedPoolEnd,
                                    '', '', '', image, adress, name)
                Lobotomy.exec_sql_query(sql_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])




