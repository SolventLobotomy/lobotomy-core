__author__ = 'w2k8, iScripters'
#
# Date:             05-05-2015
# Edited:           w2k8
#
# Date:             22 okt 2015:
# Edited:           w2k8
# Detail:          Added: Check subprocess. If Exiftool takes longer then 60 seconds to run, kill it.
# Dependency:      subprocess, psutil and shlex
#
# Date:             16 jul 2016
# Edited:           w2k8
# Detail:           Removed: subprocess.
#                   Add: multiprocessing
#
# Date:             18 jul 2016
# Edited:           w2k8
# Detail:           Added check is database table exists.
#                   Added hash from table data
#


import sys
import main
import time
import commands
import glob
from dateutil.parser import parse
import multiprocessing
from ctypes import c_int
from multiprocessing import Value, Lock, TimeoutError

Lobotomy = main.Lobotomy()
plugin = "photorec"

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

    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    dumpdir = "{}/photorec_dump".format(casedir)
    pct = 0
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_start('exifinfo', database)
    Lobotomy.plugin_pct(plugin, database, 0)

    print "plugin: {} - Database: {} - pct done: {}".format(plugin, database, str(pct))

    try:
        log = commands.getoutput("mkdir {}".format(dumpdir))
        Lobotomy.write_to_main_log(database, "mkdir: {}".format(log))
        Lobotomy.write_to_case_log(casedir, "mkdir: {}".format(log))
    except:
        pass

    command = "photorec /debug /log /logname {}/photorec.log /d {} /cmd {} fileopt,everything,enable,search".\
        format(casedir, dumpdir, imagename)

    if DEBUG:
        print "Write log: {}, Start: {}".format(database, command)
        print "Write log: {}, Start: {}".format(casedir, command)
    else:
        Lobotomy.write_to_main_log(database, "Start: {}".format(command))
        Lobotomy.write_to_case_log(casedir, "Start: {}".format(command))

    if DEBUG:
        print "Write log: {}, Database: {} Start: Running: {}".format(casedir, database, plugin)
    else:
        Lobotomy.write_to_case_log(casedir,  "Database: {} Start: Running: {}".format(database, plugin))

    if DEBUG:
        print command
    else:
        print "Running photorec - Database: {} - Please wait.".format(database)
        commands.getoutput(command)

    Lobotomy.plugin_pct(plugin, database, 5)
    print "plugin: {} - Database: {} - pct done: {}".format(plugin, database, str(5))

    if DEBUG:
        print "Write log: {}, Stop: {}".format(database, command)
        print "Write log: {}, Stop: {}".format(casedir, command)
    else:
        Lobotomy.write_to_main_log(database, "Stop: {}".format(command))
        Lobotomy.write_to_case_log(casedir, "Stop: {}".format(command))

    if DEBUG:
        print "Write log: {}, Database: {} Stop: Running: {}".format(casedir, database, plugin)
    else:
        Lobotomy.write_to_case_log(casedir,  "Database: {} Stop: Running: {}".format(database, plugin))
        Lobotomy.write_to_main_log(database, "Stop : {}".format(command))

    print "Parsing {} logfile".format(plugin)

    count = 0
    jobs = []

    with open('{}/photorec.log'.format(casedir)) as f:
        for line in f:
            # try:
            if line.startswith(casedir):
                fullfilename = line.split("\t")[0]

                if not fullfilename.endswith("mft"):
                    count += 1
                    jobs.append((fullfilename, database))

    jobscounter = len(jobs)

    p = multiprocessing.Pool(cpucount)
    p.map(execute_job, jobs)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)
    Lobotomy.plugin_stop('exifinfo', database)
    Lobotomy.plugin_pct('exifinfo', database, 100)

    hashtable(Lobotomy.get_databasedata('*', plugin, database), database)


def execute_job(work):
    mtime = atime = ctime = ''
    fullfilename, database = work

    increment()

    pct = str(float(1.0 * counter.value / jobscounter) * 100)
    pct = '{}.{}'.format(pct.split('.')[0], pct.split('.')[1][0:2])

    tmp = len(fullfilename.split("/")[-1])
    tmpfilename = fullfilename.split("/")[-1].split(".")[0]
    tmpfilepath = fullfilename[:-tmp]
    fullfilename = glob.glob(tmpfilepath + tmpfilename + "*")[0]

    try:
        filemd5 = Lobotomy.md5Checksum(fullfilename)
    except:
        filemd5 = ''
        pass

    try:
        filesha256, filemtime, fileatime, filectime, filesize = Lobotomy.sha256checksum(fullfilename)
        mtime = parse(time.ctime(filemtime)).strftime("%Y-%m-%d %H:%M:%S")
        atime = parse(time.ctime(fileatime)).strftime("%Y-%m-%d %H:%M:%S")
        ctime = parse(time.ctime(filectime)).strftime("%Y-%m-%d %H:%M:%S")
    except:
        # print filesha256, filemtime, fileatime, filectime, filesize
        pass

    filename = fullfilename.split("/")[-1]

    # Exiftool routine
    command = "exiftool {}".format(fullfilename)
    log = commands.getoutput(command)

    log = log.replace('\\', '\\\\')

    try:
        exif_SQL_cmd = "INSERT INTO exifinfo VALUES (0, '{}', '{}')".format(fullfilename, log)
        Lobotomy.exec_sql_query(exif_SQL_cmd, database)
    except:
        print "Error parse-ing file: {}".format(fullfilename)
        exif_SQL_cmd = "INSERT INTO exifinfo VALUES (0, '{}', '{}')".format(fullfilename, 'Parse error')
        Lobotomy.exec_sql_query(exif_SQL_cmd, database)
        pass

    SQL_cmd = "INSERT INTO photorec VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
            format(fullfilename, filename, filemd5, filesha256, mtime, atime, ctime)

    if DEBUG:
        print SQL_cmd
    else:
        Lobotomy.exec_sql_query(SQL_cmd, database)

    Lobotomy.plugin_pct(plugin, database, pct)
    print "plugin: {} - Database: {} - pct done: {}".format(plugin, database, str(pct))


def hashtable(data, database):
    # Tabblehash.
    # Hash the output from volatility
    tablehash = Lobotomy.hash_table(data, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)


def testdatabase(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabledata = '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `fullfilename` varchar(255) DEFAULT NULL,\
                  `filename` varchar(255) DEFAULT NULL,\
                  `md5` varchar(32) DEFAULT NULL,\
                  `sha256` char(64) DEFAULT NULL,\
                  `mtime` varchar(32) DEFAULT NULL,\
                  `atime` varchar(32) DEFAULT NULL,\
                  `ctime` varchar(32) DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;'

    Lobotomy.testdatabase(database, plugin, tabledata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {}.py <databasename>".format(plugin)
    else:
        start(sys.argv[1])
