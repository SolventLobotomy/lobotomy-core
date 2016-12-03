__author__ = 'W2k8'
#
# 04 jun 2016:      W2k8
# Plugin:           malsysproc
# Detail:

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "malsysproc"

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

    offset = pname = pid = name = path = ppid = time = priority = cmdline = count = ''
    cmdline1 = ''
    expectedparenttime = ''
    createtime = ''

    warnings = []
    warningscounter = 0
    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework') and not line.startswith('*** Failed'):
            tmp = line.split(' ')
            if line.startswith('----'):
                for l in range(len(tmp)):
                    c.append(len(tmp[l]))
                    data = 1
                # data = 0

            if data == 1 and line.startswith('...'):
                if 'Cmdline' in line:
                    cmdline1 = Lobotomy.escchar(line.split(': ')[1])
                if 'Expected Parent Time' in line:
                    expectedparenttime = line.split(': ')[1]
                if 'Create Time' in line:
                    createtime = line.split(': ')[1]
                    write_sql.append([offset, pname, pid, name, path, ppid, time, priority, cmdline, count,
                              cmdline1, expectedparenttime, createtime])
                    warnings.append(('Warning! Abnormal values found in {}. \n'
                                     'Process: {},\n'
                                     'pid: {},\n'
                                     'CmdLine: {}'.format(plugin, pname, pid, cmdline1)))
                    warningscounter = 1
                    offset = pname = pid = name = path = ppid = time = priority = cmdline = count = ''
                    cmdline1 = ''
                    expectedparenttime = ''
                    createtime = ''

            if data == 1 and line.startswith('0x') and offset != '':
                write_sql.append([offset, pname, pid, name, path, ppid, time, priority, cmdline, count,
                          cmdline1, expectedparenttime, createtime])
                offset = pname = pid = name = path = ppid = time = priority = cmdline = count = ''

            if data == 1 and line.strip('\n') == '':
                data = 0
                break
            # if data == 1 and not line.startswith('---') and not line.startswith('Found') and not line.startswith('...'):
            if data == 1 and line.startswith('0x'):
                c0 = c[0]
                c1 = c0 + c[1] + 1
                c2 = c1 + c[2] + 1
                c3 = c2 + c[3] + 1
                c4 = c3 + c[4] + 1
                c5 = c4 + c[5] + 1
                c6 = c5 + c[6] + 1
                c7 = c6 + c[7] + 1
                c8 = c7 + c[8] + 1
                c9 = c8 + c[9] + 1
                # c10 = c9 + c[10] + 1
                # c11 = c10 + c[11] + 1
                # c12 = c11 + c[12] + 1
                # c13 = c12 + c[13] + 1
                # c14 = c13 + c[14] + 1
                # c8 = c7 + c[8] + 1
                # c8 = c7 + c[8] + 1
                offset = line[0:c[0]].strip()
                pname = line[c[0]:c1].strip()
                pid = line[c1:c2].strip()
                name = line[c2:c3].strip()
                path = line[c3:c4].strip()
                ppid = line[c4:c5].strip()
                time = line[c5:c6].strip()
                priority = line[c6:c7].strip()
                cmdline = line[c7:c8].strip()
                count = line[c8:].strip()
                # time = line[c9:c10].strip()
                # cmd = line[c10:c11].strip()
                # phollow = line[c11:c12].strip()
                # spath = line[c12:].strip()

                    # data = 0

# offset = pname = pid = name = path = ppid = time = priority = cmdline = count = ''
#     cmdline1 = ''
#     expectedparenttime = ''
#     createtime = ''

                # write_sql.append([offset, pname, pid, name, path, ppid, time, priority, cmdline, count,
                #                   cmdline1, expectedparenttime, createtime])

    for line in items:
        if line.startswith('Warning'):
            warningscounter = 1
            warnings.append(line.strip('\n'))

    for offset, pname, pid, name, path, ppid, time, priority, cmdline, count, \
            cmdline1, expectedparenttime, createtime in write_sql:
    
        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}'," \
                  " '{}', '{}', '{}', '{}', '{}')".\
                  format(plugin, offset, pname, pid, name, path, ppid, time, priority, cmdline, count,
                            cmdline1, expectedparenttime, createtime)
        Lobotomy.exec_sql_query(sql_cmd, database)

    if warningscounter != 0:
        Lobotomy.register_plugin('test', database, 'warnings')
        for line in warnings:
            sql_cmd = "INSERT INTO warnings VALUES (0, '{}', '{}')".format(plugin, line)
            Lobotomy.exec_sql_query(sql_cmd, database)

        Lobotomy.register_plugin('stop', database, 'Warnings')



    return

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
