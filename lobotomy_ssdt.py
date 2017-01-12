__author__ = 'w2k8, iScripters'
#
# 08 mrt 2015:      w2k8
# Plugin:           SSDT, Verbose
#
# Date:             11-09-2015
# Detail:           Revision of SSDT.
#                   New version includes the Verbose option

import sys
import commands
import main
Lobotomy = main.Lobotomy()
plugin = "ssdt"

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

    count = 0
    counter = 0
    for line in items:
        counter += 1

    ssdt = ''
    ssdtmem = ''
    entry = ''
    pointer = ''
    syscall = ''
    owner = ''
    hookaddress = ''
    hookprocess = ''
    warningscounter = 0
    warnings = []

    for line in items:
        count += 1
        pct = str(float(1.0 * count / counter) * 100).split(".")[0]
        if line.startswith('SSDT'):
            ssdt = line.split(' ')[0]
            ssdtmem = line.split(' ')[2]
        if line.startswith('  Entry'):
            test = line.split(' ')
            entry = test[3].strip(':')
            pointer = test[4]
            syscall = test[5].strip('()')
            owner = test[8]
        if line.startswith('  ** INLINE'):
            hookaddress = line.split(' ')[6]
            hookprocess = line.split(' ')[7].strip('()')
            Lobotomy.pl('Alert: Hookadress found! {} {} {} {} {} {} {} {}'.
                        format(ssdt, ssdtmem, entry, pointer, syscall, owner, hookaddress, hookprocess))
            warningscounter = 1
            warnings.append('Warning! Possible hookadress found in process {}'.format(hookprocess))
        if entry != '' and line.split(' ')[2] == 'Entry':
            SQL_cmd = "INSERT INTO ssdt VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
                format(ssdt, ssdtmem, entry, pointer, syscall, owner, hookaddress, hookprocess)
            try:
                Lobotomy.exec_sql_query(SQL_cmd, database)
            except:
                print 'SQL Error in ', database, 'plugin: ', plugin
                print 'SQL Error: ',  SQL_cmd
                Lobotomy.write_to_case_log(casedir, "Database: " + database + " Error:  running plugin: " + plugin)
                Lobotomy.write_to_case_log(casedir, "Database: " + database + 'SQL line: ' + SQL_cmd)

            entry = ''
            pointer = ''
            syscall = ''
            owner = ''
            hookaddress = ''
            hookprocess = ''

        try:
            if pct != pcttmp:
                print "plugin: {} - Database: {} - pct done: {}".format(plugin, database, pct)
                Lobotomy.plugin_pct(plugin, database, pct)
        except:
            pass
        pcttmp = pct

    if warningscounter != 0:
        Lobotomy.register_plugin('test', database, 'warnings')
        for line in warnings:
            sql_cmd = "INSERT INTO warnings VALUES (0, '{}', '{}')".format(plugin, line)
            Lobotomy.exec_sql_query(sql_cmd, database)

        Lobotomy.register_plugin('stop', database, 'Warnings')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])