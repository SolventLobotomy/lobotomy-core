__author__ = 'w2k8, iScripters'

# 18 nov 2015:      w2k8
# Plugin:           prefetchparser
#
# Date:             10 jul 2016
# Update:           Change print format
#                   Fixed parsing error when construct isn't installed and mimikatz is in the plugin folder.
#
# Date:             18 jul 2016
# Edited:           w2k8
# Detail:           Added check is database table exists.
#                   Added hash from table data
#


import sys
import commands
import main
from dateutil.parser import parse
Lobotomy = main.Lobotomy()
plugin = "prefetchparser"

DEBUG = False


def start(database):
    # Register plugin start-time on the website
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)

    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    plugindir = Lobotomy.plugin_dir + 'plugins'

    testdatabase(database)

    command = 'vol.py --plugins={} -f {} --profile={} {}'.format(plugindir, imagename, imagetype, plugin)

    print "Running Volatility - {}, please wait.".format(plugin)
    log = commands.getoutput(command)

    try:
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(log)
        f.close()
    except:
        pass

    hashtable(log, database)

    voldata = log.split('\n')

    ltmp = 0
    l = []
    sql_data = ''
    sql_line = "INSERT INTO {} VALUES (0, ".format(plugin)

    for line in voldata:

        if not line.startswith('Volatility Foundation Volatility Framework'):

            if line.startswith('---'):
                for tmp in line.split(' '):
                    l.append(int(len(tmp)) + ltmp)
                    ltmp = ltmp + int(len(tmp)) + 1

            if not line.startswith('---') and line != '' and 'ImportError' not in line and 'Prefetch file' not in line:
                prefetchfile = line[0:l[0]].strip(' ')
                executiontime = line[l[0]:l[1]].strip(' ')
                executiontime = parse(executiontime).strftime("%Y-%m-%d %H:%M:%S")
                times = line[l[1]:l[2]].strip(' ')
                size = line[l[2] + 1:]
                sql_data = "'{}', '{}', '{}', '{}')".format(prefetchfile,
                                                            executiontime,
                                                            times,
                                                            size)
                sql_cmd = sql_line + "{}".format(sql_data)

                try:
                    #print sql_cmd
                    Lobotomy.exec_sql_query(sql_cmd, database)
                except:
                    print 'SQL Error in ', database, 'plugin: ', plugin
                    print 'SQL Error: ',  sql_cmd

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def hashtable(data, database):
    # Tabblehash.
    # Hash the output from volatility
    tablehash = Lobotomy.hash_table(data, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)


def testdatabase(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabledata = '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `prefetchfile` varchar(255) NOT NULL,\
                  `executiontime` datetime NOT NULL,\
                  `times` int(11) NOT NULL,\
                  `size` int(11) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;'

    Lobotomy.testdatabase(database, plugin, tabledata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {}.py <databasename>".format(plugin)
    else:
        start(sys.argv[1])
