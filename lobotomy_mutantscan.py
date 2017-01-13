__author__ = 'w2k8'
#
# 04 jun 2016:      w2k8
# Plugin:           mutantscan
# Detail:

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "mutantscan"

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
    threatlst = Lobotomy.read_threatlist_from_file()
    threat = ''
    threats = []
    for threat in threatlst:
        if threat.startswith('mutantscan:'):
            threats.append((threat.strip('\n').split(':')))

    c = []
    data = 0
    write_sql = []

    offset = ptr = hnd = signal = thread = cid = name = ''
    warnings = []
    warningscounter = 0
    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework') and not line.startswith('*** Failed'):
            tmp = line.split(' ')
            if line.startswith('----'):
                for l in range(len(tmp)):
                    c.append(len(tmp[l]))
                    data = 1
            if data == 1 and line.strip('\n') == '':
                data = 0
                break
            if data == 1 and not line.startswith('---') and not line.startswith('Found'):
                c0 = c[0]
                c1 = c0 + c[1] + 1
                c2 = c1 + c[2] + 1
                c3 = c2 + c[3] + 1
                c4 = c3 + c[4] + 1
                c5 = c4 + c[5] + 1
                offset = line[0:c[0]].strip()
                ptr = line[c[0]:c1].strip()
                hnd = line[c1:c2].strip()
                signal = line[c2:c3].strip()
                thread = line[c3:c4].strip()
                cid = line[c4:c5].strip()
                name = line[c5:].strip()
                for threat in threats:
                    if threat[2] in name:
                        warnings.append('Warning! Found Mutex name: {}, possible {} found.'.format(name, threat[4]))
                        warningscounter = 1
                write_sql.append([offset, ptr, hnd, signal, thread, cid, name])

    for line in items:
        if line.startswith('Warning'):
            warningscounter = 1
            warnings.append(line.strip('\n'))

    for offset, ptr, hnd, signal, thread, cid, name in write_sql:
    
        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
                  format(plugin, offset, ptr, hnd, signal, thread, cid, name)
        Lobotomy.exec_sql_query(sql_cmd, database)

    if warningscounter != 0:
        Lobotomy.register_plugin('test', database, 'warnings')
        for line in warnings:
            sql_cmd = "INSERT INTO warnings VALUES (0, '{}', '{}')".format(plugin, line)
            Lobotomy.exec_sql_query(sql_cmd, database)

        Lobotomy.register_plugin('stop', database, 'warnings')
    return

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
