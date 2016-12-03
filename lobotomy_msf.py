__author__ = 'w2k8, iScripters'
#
# 11 aug 2015:      w2k8
# Plugin:           MSF Detect
# Edit:             13 okt 2015
# Detail:           Try to detect MSF exploit
#
# Date:             09 aug 2016
# Edited:           w2k8
# Detail:           Moved common routines to main.py
#                   Plugin cleanup
# Fix:              Pid isnt always an int. Sometimes pid returns 'Kernel'
#                   Change made in database table.
#
# Date:             07 okt 2016
# Edited:           w2k8
# Detail:           When a possible infected pid is found, add Lobotomy_procstrings to the queue.


import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "msfdetect"

DEBUG = False


def start(database):
    command = []
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)

    global pidlist
    pidlist = []
    vollog = ''

    command.append('strings -a -td {} | grep stdapi > {}/meterpreter_strings.txt'.format(imagename, casedir))
    command.append('vol.py -f {} --profile={} strings -s {}/meterpreter_strings.txt'.format(imagename, imagetype, casedir))

    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl("Running Lobotomy - {}, please wait.".format(plugin))
    for cmd in command:
        tmp = cmd.split(' ')
        Lobotomy.pl('Running: {} for {}'.format(tmp[0], plugin))
        vollog = commands.getoutput(cmd)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    get_msfstrings(vollog, database)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.register_plugin('stop', database, plugin)


def get_msfstrings(log, database):
    items = log.split('\n')
    sql_list = []
    pidlist = []
    pids = ''
    for line in items:
        # try:
        if not line.startswith('Volatility Foundation Volatility'):
            stringsoffset = ''
            pid = 0
            pidoffset = ''
            vpid = 0
            vpidoffset = ''
            value = ''
            tmp = ''
            if '[FREE MEMORY]' in line:
                test = line.split('] ')[0].split('[')[1]
                # test for victim pid (infected pid)
                pids = line.split('[')[1].split(']')[0]
                if pids.count(':') > 1:
                    try:
                        vpid = pids.split(':')[1].split(' ')[1]
                        vpidoffset = pids.split(':')[2].split(' ')[0]
                    except:
                        pass
                pidoffset = test
                pid = 0
            if '[FREE MEMORY]' not in line:
                pids = line.split('[')[1].split(']')[0]
                pid = pids.split(':', 1)[0]
                pidoffset = pids.split(':', 1)[1].split(' ')[0]
                # test for victim pid (infected pid)
                if pids.count(':') > 1:
                    try:
                        vpid = pids.split(':')[1].split(' ')[1]
                        vpidoffset = pids.split(':')[2].split(' ')[0]
                    except:
                        pass
                if pid not in pidlist:
                    pidlist.append(pid)
                if vpid not in pidlist:
                    pidlist.append(vpid)
            stringsoffset = line.split(' ', 1)[0]
            value = line.split('] ')[1]
            value = Lobotomy.escchar(value)
            sql_list.append([stringsoffset, pid, pidoffset, vpid, vpidoffset, value])

    for row in sql_list:
        sql_cmd = ''
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}')".format(plugin,
                                                row[0], row[1], row[2], row[3], row[4], row[5])
        try:
            Lobotomy.exec_sql_query(sql_cmd, database)
        except:
            print 'SQL Error in ', database, 'plugin: ', plugin
            print 'SQL Error: ',  sql_cmd

    warningscounter = 0
    if len(pidlist) >= 1:
        Lobotomy.register_plugin('test', database, 'warnings')

    for pid in pidlist:
        warningscounter += 1
        warning = 'Warning! Possible Metasploit found in process {}! ({}) (!!!ABNORMAL!!!)'.format(pid, warningscounter)
        sql_cmd = "INSERT INTO warnings VALUES (0, '{}', '{}')".format(plugin, warning)
        Lobotomy.exec_sql_query(sql_cmd, database)
        # pid 0 and kernel can not be parsed.
        if pid != '0' and pid != 0 and pid != 'kernel':
            Lobotomy.add_to_queue('python {}lobotomy_procstrings.py {} {}'.format(Lobotomy.plugin_dir, database, pid), 2)
    if warningscounter != 0:
        Lobotomy.register_plugin('stop', database, 'warnings')

    return


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])