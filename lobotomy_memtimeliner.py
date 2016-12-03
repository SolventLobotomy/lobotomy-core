__author__ = 'w2k8, iScripters'
#
# 03-02: w2k8 - Aanpassen SQL query tbv modificatie website en database
#
# 12 aug 2015:  w2k8
# Fixed parse error in date/time, column date.
# Fixed issue with some filesizes. changed database value from int to varchar.
#
# date:             18 jul 2016
# Edited:           w2k8
# Detail:           added value plugin
#                   better print statements
#                   Added check is database table exists.
#                   Added hash from table data
#
# Date:             08 aug 2016
# Edited:           w2k8
# Detail:           Moved common routines to main.py
#                   Plugin cleanup
#

import sys
import os
import main
import MySQLdb
from dateutil.parser import parse


Lobotomy = main.Lobotomy()
plugin = 'memtimeliner'

DEBUG = False


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    try:
        bki = int(Lobotomy.bulkinsert)
    except:
        Lobotomy.pl('No Settings found in ini file for SQL Bulk insert. Setting to default (10000)')
        bki = 10000

    command = list()
    command.append('vol.py -f {} --profile={} timeliner --output=body --output-file={}-timeliner_time'.format(
        imagename, imagetype, imagename))
    command.append('vol.py -f {} --profile={} shellbags --output=body --output-file={}-shellbagstime'.format(
        imagename, imagetype, imagename))
    command.append('vol.py -f {} --profile={} mftparser --output=body --output-file={}-mfttime'.format(
        imagename, imagetype, imagename))
    command.append('cat {}-timeliner_time {}-mfttime {}-shellbagstime >> {}-bodytimeline.txt'.format(
        imagename, imagename, imagename, imagename))
    command.append('mactime -b {}-bodytimeline.txt -d > {}-mactime.csv'.format(
        imagename, imagename))

    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))

    for item in command:
        Lobotomy.plugin_log('start', database, plugin, casedir, item)
        os.system(item) # Commands dont give direct output.
        Lobotomy.plugin_log('stop', database, plugin, casedir, item)

    hashtable(Lobotomy.md5Checksum('{}-mactime.csv'.format(imagename)), database)

    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(imagename, database)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_voldata(imagename, database):
    sql_counter = 0
    sql_jobs = []
    jobcounter = 0

    with open("{}-mactime.csv".format(imagename)) as f:
        for line in f:
            if not line.startswith('Date,Size'):
                listitem = line.split(',')
                date = listitem[0]
                date = Lobotomy.tz_data(database, plugin, listitem[0])

                for i in range(len(listitem)):
                    listitem[i] = Lobotomy.escchar(listitem[i])

                # Lobotomy.exec_sql_query("INSERT INTO memtimeliner (id, date, size, type, mode, uid, gid, "
                #             "meta, filename)VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format
                #             (listitem[0], listitem[1], listitem[2], listitem[3], listitem[4],
                #             listitem[5], listitem[6], listitem[7]), database)


                sql_counter += 1
                sql_jobs.append((
                                '{}'.format(listitem[0]),
                                '{}'.format(listitem[1]),
                                '{}'.format(listitem[2]),
                                '{}'.format(listitem[3]),
                                '{}'.format(listitem[4]),
                                '{}'.format(listitem[5]),
                                '{}'.format(listitem[6]),
                                '{}'.format(listitem[7]),
                                ))

                if len(sql_jobs) == int(bki):

                    save_sql(sql_jobs, plugin, database)
                    sql_jobs = []
                    Lobotomy.pl('Plugin: {}, Database: {}, lines processed: {}'.
                                format(plugin, database, sql_counter))

    save_sql(sql_jobs, plugin, database)
    sql_jobs = []
    Lobotomy.pl('Plugin: {}, Database: {}, lines processed: {}'.
                format(plugin, database, sql_counter))

# Lobotomy.register_plugin('stop', database, plugin)
#
# Lobotomy.plugin_log('stop', database, plugin, casedir, command)


                # Lobotomy.exec_sql_query("INSERT INTO memtimeliner (id, date, size, type, mode, uid, gid, "
                #             "meta, filename)VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format
                #             (listitem[0], listitem[1], listitem[2], listitem[3], listitem[4],
                #             listitem[5], listitem[6], listitem[7]), database)


def save_sql(data, plugin, database):
    SQL_cmd = 'INSERT INTO {} (`date`, `size`, `type`, `mode`, `uid`, `gid`, `meta`) values'.format(plugin)
    SQL_cmd += str(data).strip('[]')
    Lobotomy.exec_sql_query(SQL_cmd, database)


def hashtable(tablehash, database):
    # Tabblehash.
    # Hash the output from volatility
    # tablehash = Lobotomy.hash_table(data, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
