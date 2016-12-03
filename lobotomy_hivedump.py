__author__ = 'w2k8, iScripters'

import sys
import main
import MySQLdb
import time
import commands
import multiprocessing
from ctypes import c_int
from multiprocessing import Value, Lock, TimeoutError

counter = Value(c_int)  # defaults to 0
counter_lock = Lock()

Lobotomy = main.Lobotomy()
plugin = "hivedump"

DEBUG = False
global database


def increment():
    with counter_lock:
        counter.value += 1


def start(database):
    global jobscounter
    global cpucount

    # Register plugin start-time on the website
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)

    cpucount = multiprocessing.cpu_count()

    jobs = []
    offsetlist = []
    hivedata = Lobotomy.get_databasedata('*', 'hivelist', database)

    for line in hivedata:

        id, voffset, poffset, hivename = line
        hivename = Lobotomy.escchar(hivename)
        offsetlist.append((voffset, hivename))

    for offset, hivename in offsetlist:
        if hivename != '[no name]':
            command = 'vol.py -f {} --profile={} {} -o {}'.format(imagename, imagetype, plugin, offset)
            jobs.append((command, offset, hivename, database, casedir, imagename))

    jobscounter = len(jobs)

    p = multiprocessing.Pool(cpucount)
    p.map(execute_job, jobs)


def execute_job(work):

    command, offset, hivename, database, casedir, imagename = work

    increment()

    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl("Running Volatility - {} at offset: {} and hivename {} - database: {}, please wait.".format(
        plugin, offset, hivename, database))
    t1 = time.time()
    vollog = commands.getoutput(command)
    t2 = time.time()
    t = '{}.{}'.format(str(t2-t1).split('.')[0], str(t2-t1).split('.')[1][3])

    Lobotomy.pl("Processing time for {} at offset: {} and hivename {} - {} seconds".format(plugin, offset, hivename, t))

    Lobotomy.save_log(imagename, '{}-{}'.format(plugin, offset), vollog)

    Lobotomy.pl('Parsing {} data with offset: {} and hivename: {}...'.format(plugin, offset, hivename))

    with open('{}-{}-{}.txt'.format(imagename, plugin, offset)) as f:
        t1 = time.time()
        Lobotomy.pl('Parsing {} data with offset: {} and hivename: {}...'.format(plugin, offset, hivename))
        for hiveitemkey in f:
            if not hiveitemkey.startswith('Volatility Foundation Volatility Framework'):
                SQL_cmd = 0
                if not hiveitemkey.startswith("Last Written"):
                    lastwritten = hiveitemkey[0:28]
                    key = hiveitemkey[29:]
                    key = key.strip("\n")
                    key = Lobotomy.escchar(key)
                    if key.startswith("\\\\$$$") or key.startswith("\\\\S-1-5") or key.startswith("\\\\SAM") \
                            or key.startswith("\\\\CMI"):
                        try:
                            key = key.split("\\", 3)[3][1:]
                        except:
                            key = key.split("\\", 3)[2][1:]
                        strippedkey = 1
                    SQL_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}')".\
                        format(plugin, offset, hivename, lastwritten, key)
                    Lobotomy.exec_sql_query(SQL_cmd, database)

        t2 = time.time()
        t = '{}.{}'.format(str(t2-t1).split('.')[0], str(t2-t1).split('.')[1][3])

        Lobotomy.pl("Processing time for parsing {} with offset: {} and hivename: {} - {} seconds".format(
            plugin, offset, hivename, t))

    Lobotomy.hashdata(database, '{}-{}'.format(plugin, offset), vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)

    Lobotomy.register_plugin('stop', database, plugin)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
