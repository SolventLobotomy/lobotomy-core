__author__ = 'W2k8'
#
# 04 jun 2016:      W2k8
# Plugin:           malprocfind
# Detail:

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "malprocfind"

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

# Offset     ProcessName     PID   PPID  Name  Path  Priority  Cmdline User  Sess  Time  CMD   PHollow SPath
# ---------- --------------- ----- ----- ----- ----- --------- ------- ----- ----- ----- ----- ------- -----
# 0x823c8830 system              4 True  True  True  True      True    True  None  True  True  True    True 
# 0x822843e8 svchost.exe      1032 True  True  True  True      True    True  True  True  True  True    True 
# 0x81e61da0 svchost.exe       940 True  True  True  True      True    True  True  True  True  True    True 
# 0x81db8da0 svchost.exe       856 True  True  True  True      True    True  True  True  True  True    True 
# 0x81c498c8 lsass.exe         868 False True  True  False     False   True  True  False True  False   True 
# 0x81da5650 winlogon.exe      624 True  True  True  True      True    True  True  True  True  True    True 
# 
# Unusual process counts:
# -----------------------
# Warning! More than 1 lsass.exe process! (1) (!!!ABNORMAL!!!)
# 
    offset = pname = pid = ppid = name = path = priority = cmdline = user = session = time = cmd = phollow = spaths = ''
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
                c6 = c5 + c[6] + 1
                c7 = c6 + c[7] + 1
                c8 = c7 + c[8] + 1
                c9 = c8 + c[9] + 1
                c10 = c9 + c[10] + 1
                c11 = c10 + c[11] + 1
                c12 = c11 + c[12] + 1
                # c13 = c12 + c[13] + 1
                # c14 = c13 + c[14] + 1
                # c8 = c7 + c[8] + 1
                # c8 = c7 + c[8] + 1
                offset = line[0:c[0]].strip()
                pname = line[c[0]:c1].strip()
                pid = line[c1:c2].strip()
                ppid = line[c2:c3].strip()
                name = line[c3:c4].strip()
                path = line[c4:c5].strip()
                priority = line[c5:c6].strip()
                cmdline = line[c6:c7].strip()
                user = line[c7:c8].strip()
                session = line[c8:c9].strip()
                time = line[c9:c10].strip()
                cmd = line[c10:c11].strip()
                phollow = line[c11:c12].strip()
                spath = line[c12:].strip()
                
                write_sql.append([offset, pname, pid, ppid, name, path, priority, cmdline, user, session, time, 
                                  cmd, phollow, spath])

    for line in items:
        if line.startswith('Warning'):
            warningscounter = 1
            warnings.append(line.strip('\n'))

    for offset, pname, pid, ppid, name, path, priority, cmdline, user, session, time, cmd, phollow, spaths in write_sql:
    
        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}'," \
                  " '{}', '{}', '{}', '{}', '{}', '{}')".\
                  format(plugin, offset, pname, pid, ppid, name, path, priority, cmdline, user, session, 
                         time, cmd, phollow, spath)
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
