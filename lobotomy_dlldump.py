__author__ = 'w2k8, iScripters'

# 11 aug 2015:      w2k8
# Plugin:           dlldump


import sys
import os
import main
import commands
import time
import multiprocessing
from ctypes import c_int
from multiprocessing import Value, Lock, TimeoutError


counter = Value(c_int)  # defaults to 0
counter_lock = Lock()

Lobotomy = main.Lobotomy()
plugin = "dlldump"

global database


def increment():
    with counter_lock:
        counter.value += 1


def start(database):
    global cpucount
    global dumpdir

    cpucount = multiprocessing.cpu_count()

    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    Lobotomy.plugin_start('exifinfo', database)
    Lobotomy.plugin_stop('exifinfo', database)

    dumpdir = "{}/dump".format(casedir)

    log = commands.getoutput("mkdir {}".format(dumpdir))
    Lobotomy.write_to_main_log(database, " mkdir: {}".format(log))
    Lobotomy.write_to_case_log(casedir, " mkdir: {}".format(log))

    command = "vol.py -f {} --profile={} {} --dump-dir={}".format(imagename, imagetype, plugin, dumpdir)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))
    vollog = commands.getoutput(command)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(vollog, database, dumpdir)

    Lobotomy.register_plugin('stop', database, plugin)
    Lobotomy.register_plugin('stop', database, 'exifinfo')


    # Register exifinfo table in table plugins to make it visible on the webpage


def parse_voldata(log, database, dumpdir):
    global jobscounter

    items = log.split('\n')
    lcounter = 0
    jobs = []
    linePointer = 0
    lastLinePointer = 0
    pointers = []

    for line in items:
        if lcounter == 2:
            for x in line.split(' '):
                pointers.append(len(x)+1)
            pointers.pop(len(pointers)-1)
            pointers.append(255)
        if lcounter > 2:
            lpart = ''
            for x in range(len(pointers)): # Loop through columns
                item = pointers[x] 
                lastLinePointer += item
                lpart += '{},'.format(line[linePointer:lastLinePointer].strip('\n').strip(' '))
                linePointer += item
            jobs.append((lpart[:-1], database, dumpdir))

            linePointer = 0
            lastLinePointer = 0
        lcounter += 1

    jobscounter = len(jobs)

    p = multiprocessing.Pool(cpucount)
    p.map(execute_job, jobs)


def execute_job(work):

    line, database, dumpdir = work
    md5 = "0"
    hashfilename = ''
    sha256 = "0"
    fullfilename = ''
    pcttmp = 0

    increment()

    pct = str(float(1.0 * counter.value / jobscounter) * 100)
    pct = '{}.{}'.format(pct.split('.')[0], pct.split('.')[1][0:2])

    t1 = time.time()
    sql_line = "INSERT INTO {} VALUES (0, ".format(plugin)
    listitem = line.split(',')
    for item in listitem:
        item = Lobotomy.escchar(item)
        sql_line = sql_line + "'{}',".format(item)
        if item == listitem[4] and item.startswith("OK:"):

            md5 = Lobotomy.md5Checksum("{}/{}".format(dumpdir, listitem[4].strip("OK: ")))
            hashfilename = listitem[4].strip("OK: ")
            sha256 = Lobotomy.sha256checksum("{}/{}".format(dumpdir, listitem[4].strip("OK: ")))[0]
            fullfilename = "{}/{}".format(dumpdir, listitem[4].strip("OK: "))

            # Exiftool routine
            # moved routine due to the msg: 'Error: DllBase is paged'
            try:
                command = "exiftool {}".format(fullfilename)
                status, log = commands.getstatusoutput(command)
                exif_SQL_cmd = "INSERT INTO exifinfo VALUES (0, '{}', '{}')".format(fullfilename, log)
                Lobotomy.exec_sql_query(exif_SQL_cmd, database)
            except:
                Lobotomy.pl("Error parse-ing file: {}".format(fullfilename))
                exif_SQL_cmd = "INSERT INTO exifinfo VALUES (0, '{}', '{}')".format(fullfilename, 'Parse error')
                Lobotomy.exec_sql_query(exif_SQL_cmd, database)
        else:
            md5 = "0"
            hashfilename = ''
            sha256 = "0"
            fullfilename = ''
    sql_line = sql_line + "'{}','{}','{}','{}')".format(md5, sha256, hashfilename, fullfilename)
    Lobotomy.exec_sql_query(sql_line, database)
    t2 = time.time() - t1
    t = '{}.{}'.format(str(t2).split('.')[0], str(t2).split('.')[1][0:2])

    try:
        if pct != pcttmp:
            Lobotomy.pl("plugin: {} - Database: {} - pct done: {} - pid: {} - processing time: {}".format(plugin,
                                                                            database, str(pct), os.getpid(), t))
            Lobotomy.plugin_pct(plugin, database, pct)
    except:
        pass
    pcttmp = pct


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
