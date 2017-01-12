__author__ = 'W2k8, iScripters'
#
# Date:             19 jul 2016
# Edited:           W2k8


import sys
import commands
import main
Lobotomy = main.Lobotomy()
# plugin = "ldrmodules"
plugin = 'ldrmodules_v'
pluginname = 'ldrmodules'
DEBUG = False


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py -f {} --profile={} {} -v'.format(imagename, imagetype, pluginname)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))
    vollog = commands.getoutput(command)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(vollog, database)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_voldata(vollog, database):
    data = vollog.split('\n')

    lp = []
    Sql_cmd = ''
    loadpath = []
    mempath = []
    initpath = []
    writesql = []
    pid = 0
    tmpmem = 0
    tmpload = 0
    tmpinit = 0
    pidininit = ''
    pidinmem = ''
    pidinload = ''
    datahash = []
    warnings = []
    for line in data:
        #
        # Get the length of the columns
        #
        if line.startswith('-----'):
            lenline = line.split(' ')
            for item in lenline:
                lp.append(int(len(item) + 1))

        testpath = line.split(': ')
        if 'Load Path' in line:
            for item in testpath:
                if item != '':
                    item = item.strip(' ')
                    loadpath.append(item)
        if 'Init Path' in line:
            for item in testpath:
                if item != '':
                    item = item.strip(' ')
                    initpath.append(item)
        if 'Mem Path' in line:
            for item in testpath:
                if item != '':
                    item = item.strip(' ')
                    mempath.append(item)
        if pid == 1:
            if 'True' in pidinload and tmpload == 0:
                for item in loadpath:
                    writesql.append(item)
                    tmpload = 1
                if len(loadpath) == 2:
                    writesql.append('')
                    datahash.append('')
            if 'False' in pidinload and tmpload == 0:
                for tmp in range(3):
                    writesql.append('')
                    datahash.append('')
                    tmpload = 1
            if 'True' in pidininit and tmpinit == 0:
                for item in initpath:
                    writesql.append(item)
                    datahash.append(item)
                    tmpinit = 1
                if len(initpath) == 2:
                    writesql.append('')
                    datahash.append('')
            if 'False' in pidininit and tmpinit == 0:
                for tmp in range(3):
                    writesql.append('')
                    datahash.append('')                    
                    tmpinit = 1
            if 'True' in pidinmem and tmpmem == 0:
                for item in mempath:
                    writesql.append(item)
                    datahash.append(item)
                    tmpmem = 1
                if len(mempath) == 2:
                    writesql.append('')                    
                    datahash.append('')
            if 'False' in pidinmem and tmpmem == 0:
                for tmp in range(3):
                    writesql.append('')
                    datahash.append('')
                    tmpmem = 1

        if tmpload == 1 and tmpinit == 1 and tmpmem == 1 and pid == 1:
            Sql_cmd = ''
            Sql_prefix = "INSERT INTO {} VALUES (0,".format(plugin)
            for item in writesql:
                try:
                    item = Lobotomy.escchar(item)
                except AttributeError: #'int' object has no attribute 'replace'
                    pass
                Sql_cmd = Sql_cmd + "'{}',".format(item)
            Sql_cmd = Sql_prefix + Sql_cmd[:-1] + ")"
            Lobotomy.exec_sql_query(Sql_cmd, database)

            if writesql[3] == 'True' and \
                writesql[4] == 'False' and \
                writesql[5] == 'True' and \
                writesql[6] == '':
                warnings.append('Warning! Possible unlinked dll in Pid: {}, processname: {}. See {} for more information'.\
                    format(writesql[0], writesql[1], plugin))

            pidininit = ''
            pidinmem = ''
            pidinload = ''

            writesql = []
            mempath = []
            loadpath = []
            pid = 0
            tmpmem = 0
            tmpload = 0
            tmpinit = 0
            initpath = []

        try:
            if int(line[:8].strip(' ')):
                pidpid = int(line[:8].strip(' '))
                pidprocess = line[lp[0]:lp[0] + lp[1]].strip(' ')
                pidbase = line[lp[0]+lp[1]:lp[0]+lp[1]+lp[2]].strip(' ')
                pidinload = line[lp[0]+lp[1]+lp[2]:lp[0]+lp[1]+lp[2]+lp[3]].strip(' ')
                pidininit = line[lp[0]+lp[1]+lp[2]+lp[3]:lp[0]+lp[1]+lp[2]+lp[3]+lp[4]].strip(' ')
                pidinmem = line[lp[0]+lp[1]+lp[2]+lp[3]+lp[4]:lp[0]+lp[1]+lp[2]+lp[3]+lp[4]+lp[5]].strip(' ')
                pidpath = line[lp[0]+lp[1]+lp[2]+lp[3]+lp[4]+lp[5]:]

                writesql.append(int(line[:8].strip(' ')))
                writesql.append(line[lp[0]:lp[0] + lp[1]].strip(' '))
                writesql.append(line[lp[0]+lp[1]:lp[0]+lp[1]+lp[2]].strip(' '))
                writesql.append(line[lp[0]+lp[1]+lp[2]:lp[0]+lp[1]+lp[2]+lp[3]].strip(' '))
                writesql.append(line[lp[0]+lp[1]+lp[2]+lp[3]:lp[0]+lp[1]+lp[2]+lp[3]+lp[4]].strip(' '))
                writesql.append(line[lp[0]+lp[1]+lp[2]+lp[3]+lp[4]:lp[0]+lp[1]+lp[2]+lp[3]+lp[4]+lp[5]].strip(' '))
                writesql.append(line[lp[0]+lp[1]+lp[2]+lp[3]+lp[4]+lp[5]:])

                pid = 1
        except:
            pass

    if len(warnings) > 0:
        Lobotomy.register_plugin('test', database, 'warnings')
        for warning in warnings:
            sql_cmd = "INSERT INTO warnings VALUES (0, '{}', '{}')".format(plugin, warning)
            Lobotomy.exec_sql_query(sql_cmd, database)
    if len(warnings) > 0:
        Lobotomy.register_plugin('stop', database, 'warnings')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
