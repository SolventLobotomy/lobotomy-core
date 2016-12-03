__author__ = 'w2k8, iScripters'
#
# Date:             19 jul 2016
# Edited:           w2k8
# Detail:           Added check if database table exists.
#                   Added hash from table data
#

import sys
import commands
import main
Lobotomy = main.Lobotomy()
plugin = "ldrmodules"
pluginname = 'ldrmodules_v'
DEBUG = False


def start(database):
    # Register plugin start-time on the website
    Lobotomy.plugin_start(pluginname, database)
    Lobotomy.plugin_pct(pluginname, database, 1)

    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    command = 'vol.py -f {} --profile={} {} -v'.format(imagename, imagetype, plugin)

    testdatabase(database)

    if DEBUG:
        print "Write log: {}, Start: {}".format(database, command)
        print "Write log: {}, Start: {}".format(casedir, command)
    else:
        Lobotomy.write_to_main_log(database, "Start: {}".format(command))
        Lobotomy.write_to_case_log(casedir, "Start: {}".format(command))

    if DEBUG:
        print command
    else:
        print "Running Volatility - {}, please wait.".format(pluginname)
        vollog = commands.getoutput(command)

    try:
        f = open('{}-{}.txt'.format(imagename, pluginname), 'w')
        f.write(vollog)
        f.close()
    except:
        pass

    if DEBUG:
        print "Write log: {}, Stop: {}".format(database, command)
        print "Write log: {}, Stop: {}".format(casedir, command)
    else:
        Lobotomy.write_to_main_log(database, "Stop: {}".format(command))
        Lobotomy.write_to_case_log(casedir, "Stop: {}".format(command))

    if DEBUG:
        print 'Write log: {}, database: {} Start plugin: {}'.format(casedir, database, pluginname)
    else:
        Lobotomy.write_to_case_log(casedir, 'Database: {} Start plugin: {}'.format(database, pluginname))

    hashtable(vollog, database)

    try:
        logcounter = 0
        for loglines in vollog.split('\n'):
            if folder in loglines:
                logcounter += 1
    except:
        pass

    print 'Parsing {} data...'.format(plugin)
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

    for line in vollog.split('\n'):
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
            Sql_prefix = "INSERT INTO {} VALUES (0,".format(pluginname)
            for item in writesql:
                try:
                    item = item.replace('\\', '\\\\')
                except:
                    pass
                Sql_cmd = Sql_cmd + "'{}',".format(item)
            Sql_cmd = Sql_prefix + Sql_cmd[:-1] + ")"

            Lobotomy.exec_sql_query(Sql_cmd, database)

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
                # for testing
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

    if DEBUG:
        print 'Write log: {}, database: {} Stop plugin: {}'.format(casedir, database, pluginname)
    else:
        Lobotomy.write_to_case_log(casedir, 'Database: {} Stop plugin: {}'.format(database, pluginname))
        Lobotomy.plugin_stop(pluginname, database)
        Lobotomy.plugin_pct(pluginname, database, 100)


def hashtable(data, database):
    # Tabblehash.
    # Hash the output from volatility
    tablehash = Lobotomy.hash_table(data, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(pluginname, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)


def testdatabase(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabledata = '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `process` varchar(255) NOT NULL,\
                  `base` varchar(18) NOT NULL,\
                  `inload` varchar(5) NOT NULL,\
                  `ininit` varchar(5) NOT NULL,\
                  `inmem` varchar(5) NOT NULL,\
                  `mappedpath` varchar(255) NOT NULL,\
                  `loadpath` varchar(255) DEFAULT NULL,\
                  `loadpathpath` varchar(255) DEFAULT NULL,\
                  `loadpathprocess` varchar(255) DEFAULT NULL,\
                  `initpath` varchar(255) DEFAULT NULL,\
                  `initpathpath` varchar(255) DEFAULT NULL,\
                  `initpathprocess` varchar(255) DEFAULT NULL,\
                  `mempath` varchar(255) DEFAULT NULL,\
                  `mempathpath` varchar(255) DEFAULT NULL,\
                  `mempathprocess` varchar(255) DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;'

    Lobotomy.testdatabase(database, pluginname, tabledata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
