__author__ = 'w2k8, iScripters'

#
# Date:             07 okt 2016
# Edited:           w2k8
# Detail:           Implement AESKeyFind into lobotomy
#

import sys
import commands
import main
Lobotomy = main.Lobotomy()
plugin = "aeskeys"


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'aeskeyfind -v {} > {}-{}.txt'.format(imagename, imagename, plugin)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running AESKeyFind for Lobotomy - {}, please wait.'.format(plugin))
    vollog = commands.getoutput(command)

    # sometime the progress from aseskeyfind is saved in the output.
    # Lobotomy.save_log(imagename, plugin, vollog)
    aeskeyfindlog = ''
    with open('{}-{}.txt'.format(imagename, plugin)) as f:
        for line in f:
            aeskeyfindlog += '{}'.format(line)

    Lobotomy.hashdata(database, plugin, aeskeyfindlog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(aeskeyfindlog, database)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_voldata(log, database):
    items = log.split('\n')
    aeskeyfound = 0
    constrains = 0
    keytype = ''
    offset = ''
    aeskey = ''
    constrainskey = ''
    aesextendedkey = ''
    aeskeys = []
    for line in items:
        if line.startswith('FOUND POSSIBLE'):
            if line.split(' ')[-1] != '':
                offset = line.split(' ')[-1]
            elif line.split(' ')[-2] != '':
                offset = line.split(' ')[-2]
            keytype = line.split(' ')[2]
        if line.startswith('KEY:'):
            aeskey = line.split(' ')[1]

        if aeskeyfound == 1:
            if line == '':
                aeskeyfound = 0
            else:
                aesextendedkey += '{}\n'.format(line)
        if line.startswith('EXTENDED KEY:'):
            # print 'extended key'
            # We need to get the next few lines.
            aeskeyfound = 1
            aesextendedkey = ''

        if constrains == 1:
            if line == '':
                constrains = 0
            else:
                constrainskey += '{}\n'.format(line)
        if line.startswith('CONSTRAINTS'):
            constrains = 1
            constrainskey = ''

        if constrainskey != '' and line == '':
            aeskeys.append((offset, keytype, aeskey, aesextendedkey, constrainskey))
            aeskey = ''
            offset = ''
            aeskeyfound = 0
            constrains = 0
            keytype = ''
            constrainskey = ''
            aesextendedkey = ''
    for key in aeskeys:
        sql_line = "INSERT INTO {} VALUES (".format(plugin)
        sql_line = sql_line + "0, '{}', '{}', '{}', '{}', '{}')".\
            format(key[0], key[1], key[2], key[3], key[4],)
        Lobotomy.exec_sql_query(sql_line, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
