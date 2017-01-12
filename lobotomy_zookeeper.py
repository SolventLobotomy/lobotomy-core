__author__ = 'w2k8, iScripters'

#
# Date:             06-07-2015
# Edited:           w2k8
#
# Date:             18 jul 2016
# Edited:           w2k8
# Detail:           Added check is database table exists.
#                   Added hash from table data
#

import sys
import main
import os
import commands
import main
import time

try:
    import bitstring
except:
    print 'Missing plugin: Bitstring'
    print 'Please install Bitstring'
    print 'sudo pip install bitstring'
    exit()

Lobotomy = main.Lobotomy()
plugin = "pe_scan"

DEBUG = False


def start(database):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    # imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    totaldirs = 0

    testdatabase(database)

    for subdir, dirs, files in os.walk(casedir):
        for folders in dirs:
            for subdir1, dirs1, files1 in os.walk('{}/{}'.format(subdir, folders)):
                totaldirs += 1
    print 'Zookeeper is going to run on {} folders'.format(totaldirs)
    for subdir, dirs, files in os.walk(casedir):
        for folders in dirs:
            for subdir1, dirs1, files1 in os.walk('{}/{}'.format(subdir, folders)):
                print 'Running zookeeper on folder: {}'.format(subdir1)
                command = "cd zookeeper && python ZooKeeper.py -t {} -d {}".format(database, subdir1)
                if DEBUG:
                    print "Write log: {}, Start: {}".format(database, command)
                    print "Write log: {}, Start: {}".format(casedir, command)
                else:
                    Lobotomy.write_to_main_log(database, "Start: {}".format(command))
                    Lobotomy.write_to_case_log(casedir, "Start: {}".format(command))

                fullfilename = ''
                pe_compiletime = ''
                original_filename = ''
                pe_packer = ''
                filetype = ''
                pehash = ''
                md5 = ''
                pe_language = ''
                pe_dll = ''
                filename = ''
                sha = ''
                tag = ''
                filesize = ''
                yara_results = ''

                print "Running ZooKeeper, please wait."
                log = commands.getoutput(command)

                Lobotomy.write_to_case_log(casedir, "Stop : {}".format(command))
                Lobotomy.write_to_case_log(casedir, "Database: {} Start: Parsing ZooKeeper output: {}".
                                           format(database, plugin))

                sql_prefix = "INSERT INTO {} VALUES (0, ".format(plugin)
                try:
                    f = open('{}-zookeeperlog.txt'.format(imagename), 'a')
                    f.write(log)
                    f.close()
                except:
                    pass
                items = log.split('\n')
                print 'Parsing Zookeeper data'
                for item in items:
                    if item.startswith('fullfilename'):
                        try:
                            fullfilename = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('pe_compiletime'):
                        try:
                            pe_compiletime = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('original_filename'):
                        try:
                            original_filename = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('pe_packer'):
                        try:
                            pe_packer = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('filetype'):
                        try:
                            filetype = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('pehash'):
                        try:
                            pehash = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('md5'):
                        try:
                            md5 = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('pe_language'):
                        try:
                            pe_language = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('pe_dll'):
                        try:
                            pe_dll = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('filename'):
                        try:
                         filename = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('sha'):
                        try:
                            sha = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('tag'):
                        try:
                            tag = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('filesize'):
                        try:
                            filesize = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('yara_results'):
                        try:
                            yara_results = item.split(' ', 1)[1]
                        except:
                            pass
                    if item.startswith('*****'):

                        sql_line = sql_prefix + "'{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}'".\
                            format(fullfilename, original_filename, pe_compiletime, pe_packer, filetype, pe_language, pe_dll,
                                   filename, md5, sha, pehash, tag, filesize, yara_results + "')")[:-1]
                        try:
                            Lobotomy.exec_sql_query(sql_line, database)
                            fullfilename = ''
                            pe_compiletime = ''
                            original_filename = ''
                            pe_packer = ''
                            filetype = ''
                            pehash = ''
                            md5 = ''
                            pe_language = ''
                            pe_dll = ''
                            filename = ''
                            sha = ''
                            tag = ''
                            filesize = ''
                            yara_results = ''
                        except:
                            print 'Error sql query: {} - {}'.format(sql_line, database)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)
    Lobotomy.register_plugin('stop', database, 'exifinfo')

    with open('{}-zookeeperlog.txt'.format(imagename)) as f:
        log = f.read()
    hashtable(log, database)


def hashtable(data, database):
    # Tabblehash.
    # Hash the output from volatility
    tablehash = Lobotomy.hash_table(data, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)


def testdatabase(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabledata = '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `fullfilename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `original_filename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_compiletime` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_packer` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filetype` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_language` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_dll` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `md5` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `sha` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pehash` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `tag` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filesize` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `yara_results` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;'

    Lobotomy.testdatabase(database, plugin, tabledata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <database>"
    else:
        start(sys.argv[1])
