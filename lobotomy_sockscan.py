__author__ = 'w2k8, iScripters'
#
# 18-02: w2k8 - Sockscan version 0.1
#
# Date:             21 jul 2016
# Edited:           w2k8
# Detail:           Rebuild plugin.
#                   Added check if database table exists.
#                   Added hash from table data
# Fixmed            Error with memorydump '' in sockscan.as
#                   The output data give pid numbers with dots. (long (truncated) pid-numbers)
#                   rebuild database table where pid isnt a int but a varchar.
#
#                   vol.py -f sockscan
#                   Volatility Foundation Volatility Framework 2.4
#                   Offset(P)       PID   Port  Proto Protocol        Address         Create Time
#                   ---------- -------- ------ ------ --------------- --------------- -----------
#                   0x01da0240 152...53    836   8457 -               3.30.4.33       9194-03-30 18:09:33 UTC+0000
#                   0x01e48748        0   1280     32 MERIT-INP       0.5.0.0         -
#

import sys
import commands
import main

Lobotomy = main.Lobotomy()
plugin = "sockscan"

DEBUG = False


def start(database):
    Lobotomy.plugin_start(plugin, database)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]

    testdatabase(database)

    command = "vol.py -f {} --profile={} {}".format(imagename, imagetype, plugin)

    Lobotomy.write_to_main_log(database, " Start: {}".format(command))
    Lobotomy.write_to_case_log(casedir, " Start: {}".format(command))
    if DEBUG:
        print command
    else:
        print "Running Volatility - {}, please wait.".format(plugin)
        vollog = commands.getoutput(command)

    Lobotomy.write_to_main_log(database, " Stop: {}".format(command))
    Lobotomy.write_to_case_log(casedir, " Stop: {}".format(command))

    try:
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(vollog)
        f.close()
    except:
        pass

    hashtable(vollog, database)

    lines = vollog.split('\n')
    print 'Parsing {} data...'.format(plugin)

    for line in lines:
        if not line.startswith('Volatility Foundation Volatility') \
                and not line.startswith('----')\
                and not line.startswith('Offset'):
            line = line.replace('\\', '\\\\').replace("'", "\"").replace('"', '\"')

            offset = line[0:10].strip(" ")
            pid = line[11:19].strip(" ")
            port = line[20:26].strip(" ")
            proto = line[26:34].strip(" ")
            protocol = line[34:49].strip(" ")
            adress = line[50:66].strip(" ")
            createtime = line[66:86]

            SQL_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(plugin,
                                                    offset, pid, port, proto, protocol, adress, createtime)
            if DEBUG:
                print SQL_cmd
            else:
                Lobotomy.exec_sql_query(SQL_cmd, database)

    if DEBUG:
        print 'Write log: {}, database: {} Stop plugin: {}'.format(casedir, database, plugin)
    else:
        Lobotomy.write_to_case_log(casedir, 'Database: {} Stop plugin: {}'.format(database, plugin))
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
                  `offset` varchar(18) NOT NULL,\
                  `pid` varchar(11) NOT NULL,\
                  `port` int(11) NOT NULL,\
                  `proto` int(11) NOT NULL,\
                  `protocol` varchar(255) NOT NULL,\
                  `address` varchar(255) NOT NULL,\
                  `createtime` varchar(32) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;'

    Lobotomy.testdatabase(database, plugin, tabledata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {}.py <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
