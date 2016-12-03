__author__ = 'w2k8, iScripters'
# Date:             24 jul 2016
# Edited:           w2k8
# Detail:           Created new plugin for lobotomy
#

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "joblinks"


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command25 = 'vol.py -f {} --profile={} {} --output=greptext'.format(imagename, imagetype, plugin)
    command24 = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)
    Lobotomy.plugin_log('start', database, plugin, casedir, command24)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))

    vollog = commands.getoutput('vol.py -h')
    if vollog.startswith('Volatility Foundation Volatility Framework 2.5'):
        volver = '2.5'
        vollog = commands.getoutput(command25)
    else:
        volver = '2.4'
        vollog = commands.getoutput(command24)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command24)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(vollog, database, volver)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_voldata(log, database, volver):
    data = log.split('\n')
    sql_data = []
    lp = []
    for line in data:

        if line.startswith('-----'):
            for item in line.split():
                lp.append(int(len(item) + 1))

        if not line.startswith("Offset") and not line.startswith('Volatility Foundation Volatility')\
                and not line.startswith('---') and not line.startswith('****'):
            line = line.strip("\n")
            line = Lobotomy.escchar(line)

            # Volatility Version 2.5
            if volver == '2.5':
                if line.startswith('>|'):
                    tmp, offset, name, pid, ppid, sess, jobsess, wow64, total, active, term, \
                                    joblink, process = line.split('|')
                    sql_data.append((offset, name, pid, ppid, sess, jobsess, wow64, total, active, term,
                                     joblink, process))

            # Volatility Version 2.4
            if volver == '2.4':
                tmpl = 0
                counter = 0
                data = []
                for l in lp:
                    counter += 1
                    if len(lp) == counter:
                        data.append(str(line[tmpl:]))
                    else:
                        data.append(line[tmpl:tmpl+l].strip())
                        tmpl += l
                sql_data.append(data)

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
