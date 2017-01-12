__author__ = 'w2k8, iScripters'

# Plugin:           Lobotomy PE Scanner
# Date:             06-07-2015
# Edited:           w2k8
#
# 02 sep 2015:      w2k8
#  Detail:          Fixed: An issue where the scripts try's to write a wrong sql query.
#                   there can sometimes a ' in the text.
#                   Change: Add plugin name in output.
# 22 okt 2015:      w2k8
#  Detail:          Added: Check subprocess. If PEScanner takes longer then 60 seconds to run, kill it.
#  Dependency:      subprocess, psutil and shlex
#
# Date:             18 jul 2016
# Edited:           w2k8
# Detail:           Added check is database table exists.
#                   Added hash from table data
#

import os
import sys
import main
import commands
import time
import multiprocessing
from ctypes import c_int
from multiprocessing import Value, Lock, TimeoutError


Lobotomy = main.Lobotomy()
plugin = "pe_scanner"

DEBUG = False

counter = Value(c_int)  # defaults to 0
counter_lock = Lock()

global database


import subprocess as sub
import threading


class RunCmd(threading.Thread):
    def __init__(self, cmd, timeout):
        threading.Thread.__init__(self)
        self.cmd = cmd
        self.timeout = timeout

    def run(self):
        self.p = sub.Popen(self.cmd)#, stdout=subprocess.PIPE)
        self.p.wait()

    def Run(self):
        self.start()
        self.join(self.timeout)

        if self.is_alive():
            self.p.terminate()      #use self.p.kill() if process needs a kill -9
            self.join()


def increment():
    with counter_lock:
        counter.value += 1


def start(database):
    global jobscounter
    global cpucount

    cpucount = multiprocessing.cpu_count()

    testdatabase(database)

    Lobotomy.plugin_start('pe_scanner', database)
    plugindir = Lobotomy.plugin_dir
    Lobotomy.plugin_pct('pe_scanner', database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]

    count = 0
    jobs = []

    for subdir, dirs, files in os.walk(casedir):
        for folders in dirs:
            for subdir1, dirs1, files1 in os.walk(subdir + '/' + folders):
                for lfile in files1:
                    filename = os.path.join(subdir1, lfile)
                    if not filename.endswith('.txt'):
                        count += 1
                        jobs.append((('./mcb_pescanner.py', filename, database), filename, count, database))

    jobscounter = len(jobs)

    p = multiprocessing.Pool(cpucount)

    p.map(execute_job, jobs)

    Lobotomy.plugin_stop('pe_scanner', database)
    Lobotomy.plugin_pct('pe_scanner', database, 100)
    Lobotomy.register_plugin('stop', database, 'exifinfo')

    hashtable(Lobotomy.get_databasedata('*', 'pe_scanner', database), database)


def execute_job(work):

    command, filename, count, database = work
    command, args1, args2 = command

    increment()

    pct = str(float(1.0 * counter.value / jobscounter) * 100)
    pct = '{}.{}'.format(pct.split('.')[0], pct.split('.')[1][0:2])
    t1 = time.time()
    print "Lobotomy PEScanner - ProcessID: ", os.getpid()
    print "Lobotomy PEScanner - Percentage done: ", pct
    print "Lobotomy PEScanner - file: {} of {}".format(str(counter.value), str(jobscounter))
    print "Lobotomy PEScanner - Current filename: ", filename

    # Writing to the database is done in the sub plugin mcb_pescanner.py
    RunCmd([command, args1, args2], 30).Run()

    t2 = time.time()
    print "Lobotomy PEScanner - Processing time: ", t2-t1
    Lobotomy.plugin_pct('pe_scanner', database, pct)


def hashtable(data, database):
    # Tabblehash.
    # Hash the output from volatility
    tablehash = Lobotomy.hash_table(data, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)


def testdatabase(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabledata = '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `filename` varchar(256) DEFAULT NULL,\
                  `pe_blob` longblob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;'

    Lobotomy.testdatabase(database, plugin, tabledata)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: pe_scanner.py <database>"
    else:
        start(sys.argv[1])

