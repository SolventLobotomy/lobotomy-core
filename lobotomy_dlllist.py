__author__ = 'w2k8, iScripters'

#
# 11 aug 2015:      w2k8
# Plugin:           dlllist


import sys
import commands
import main

Lobotomy = main.Lobotomy()
plugin = "dlllist"

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

    count = 0
    counter = 0
    for line in items:
        counter += 1

    dll = 1
    linenr = 0
    proc = ""
    cmd = ""
    sp = ""
    base = ""
    size = ""
    loadcount = ""
    path = ""

    for line in items:
        line = Lobotomy.escchar(line)
        count += 1
        pct = str(float(1.0 * count / counter) * 99).split(".")[0]
        if line.startswith("**********************") or line.startswith("Volatility"):
            linenr = 0
            dll = 0
        else:
            linenr += 1
            if linenr == 1:
                a, b = line.split(":") # should be process and pid.
                proc = a.split(" ")[0]
                pid = b.strip(" ").strip("\n")
            if linenr == 2:
                if line.startswith('Unable to read PEB for task'):
                    cmd = line.strip('\n')
                    SQL_cmd = "INSERT INTO dlllist VALUES (0, '{}', '{}', '{}', '', '', '', '', '')". \
                        format(proc, pid, cmd)
                    if DEBUG:
                        print SQL_cmd
                    else:
                        Lobotomy.exec_sql_query(SQL_cmd, database)
                        Lobotomy.plugin_pct(plugin, database, pct)
                        base = ''
                        size = ''
                        loadcount = ''
                        path = ''
                if line.startswith("Command"):
                    cmd = line.split(": ")[1].strip("\n")
                else:
                    cmd = line.strip("\n")
            if linenr == 3:
                if line.startswith("Service"):
                    sp = line
                else:
                    sp = ""
            if dll == 1:
                base = line[0:10].strip(" ")
                size = line[11:22].strip(" ")
                loadcount = line[23:33].strip(" ")
                path = line[33:].strip('\n')
            if line.startswith("----------"):
                dll = 1
            if proc != "" and dll == 1 and path != '':
                SQL_cmd = "INSERT INTO dlllist VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')". \
                    format(proc, pid, cmd, sp, base, size, loadcount, path)
                if DEBUG:
                    print SQL_cmd
                else:
                    Lobotomy.exec_sql_query(SQL_cmd, database)
                    Lobotomy.plugin_pct(plugin, database, pct)
                    base = ''
                    size = ''
                    loadcount = ''
                    path = ''


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
