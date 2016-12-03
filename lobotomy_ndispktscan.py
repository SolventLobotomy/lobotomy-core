__author__ = 'w2k8'
#
# 04 jun 2016:      w2k8
# Plugin:           ndispktscan
# Detail:           Get the users and where possible the passwords from a memorydump

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "ndispktscan"

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

    c = []
    data = 0
    write_sql = []

    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework') and not line.startswith('*** Failed'):
            tmp = line.split(' ')
            if line.startswith('----'):
                for l in range(len(tmp)):
                    c.append(len(tmp[l]))
                    data = 1
            if data == 1 and not line.startswith('---') and not line.startswith('Found'):
                c0 = c[0]
                c1 = c0 + c[1] + 1
                c2 = c1 + c[2] + 1
                c3 = c2 + c[3] + 1
                c4 = c3 + c[4] + 1
                c5 = c4 + c[5] + 1
                c6 = c5 + c[6] + 1
                c7 = c6 + c[7] + 1
                # c8 = c7 + c[8] + 1
                offset = line[0:c[0]].strip()
                smac = line[c[0]:c1].strip()
                dmac = line[c1:c2].strip()
                port = line[c2:c3].strip()
                sip = line[c3:c4].strip()
                dip = line[c4:c5].strip()
                sport = line[c5:c6].strip()
                dport = line[c6:c7].strip()
                flags = line[c7:].strip()
                write_sql.append([offset, smac, dmac, port, sip, dip, sport, dport, flags])
                # print offset, smac, dmac, port, sip, dip, sport, dport, flags

    for offset, smac, dmac, port, sip, dip, sport, dport, flags in write_sql:

        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
                  format(plugin, offset, smac, dmac, port, sip, dip, sport, dport, flags)
        Lobotomy.exec_sql_query(sql_cmd, database)
    return


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
