__author__ = 'w2k8, iScripters'

# 11 aug 2015:      w2k8
# Plugin:           procstrings
# Edit:             04 okt 2016
# Detail:           Try to match strings with various sections in a process
#                   This plugin doesnt get called from autostart.
#                   This plugin needs the get triggered from another plugin.


import sys
import commands
import main

Lobotomy = main.Lobotomy()

plugin = "procstrings"


def start(database, looking_pid):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    jobs = []
    pcttmp = 0

    try:
        bki = int(Lobotomy.bulkinsert)
    except:
        Lobotomy.pl('No Settings found in ini file for SQL Bulk insert. Setting to default (10000)')
        bki = 10000

    plugindir = Lobotomy.plugin_dir
    command = []
    dumpdir = "{}/memdump".format(casedir)

    try:
        log = commands.getoutput("mkdir {}".format(dumpdir))
        Lobotomy.write_to_main_log(database, " mkdir: {}".format(log))
        Lobotomy.write_to_case_log(casedir, " mkdir: {}".format(log))
    except:
        pass

    Lobotomy.pl('Running Lobotomy - {} on pid: {}, please wait.'.format(plugin, looking_pid))

    Lobotomy.pl('Reading data from database')
    data_memmap = Lobotomy.get_databasedata('pid, name, virtual, physical, size, dumpfileoffset',
                        'memmap where pid = "{}"'.format(looking_pid), database)

    Lobotomy.pl('Dumping process memory')
    log = commands.getoutput('vol.py -f {} --profile={} memdump -p {} --dump-dir={}'.
                   format(imagename, imagetype, looking_pid, dumpdir))

    Lobotomy.pl('Dumping strings from process memory')
    log = commands.getoutput('strings -6 -a -tx {}/{}.dmp > {}/{}.txt'.
                   format(dumpdir, looking_pid, dumpdir, looking_pid))

    Lobotomy.pl('Disassembling binary')
    log = commands.getoutput('python {}distorm/sample.py --b32 {}/procdump/executable.{}.exe > {}.{}.distorm.txt'.
                   format(plugindir, casedir, looking_pid, imagename, looking_pid))

    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Lobotomy plugin - {}, please wait.'.format(plugin))

    vollog = []
    try:
        with open('{}/{}.txt'.format(dumpdir, looking_pid)) as f:
            for line in f:
                jobs.append((looking_pid, line.strip('\n')))
    except IOError:
        pass #

    distorm = []
    try:
        with open('{}.{}.distorm.txt'.format(imagename, looking_pid)) as f:
            for line in f:
                    distorm.append(line)
    except IOError:
        pass #

    jobscounter = len(jobs)

    sql_counter = 0
    sql_jobs = []
    jobcounter = 0
    for pid, item in jobs:

        pct = str(float(1.0 * jobcounter / jobscounter) * 100)
        pct = '{}.{}'.format(pct.split('.')[0], pct.split('.')[1][0:2])

        try:
            if pct != pcttmp:
                Lobotomy.pl("plugin: {} - Database: {} - pct done: {} - pid: {}"
                            .format(plugin, database, str(pct), looking_pid))
                Lobotomy.plugin_pct(plugin, database, pct)
        except:
            pass

        jobcounter += 1
        pcttmp = pct

        for a in item:
            if item[0] == ' ':
                item = item[1:]
                # print item
            else:
                break

        if len(item.split(' ', 1)) == 2:
            offset, string = item.split(' ', 1)
            string = string.strip('\n')

            offsetint = int(offset.strip(), 16)

            for line in data_memmap:
                offsetmemmap = int(line[5], 16)
                size = line[4]
                if offsetint >= offsetmemmap and offsetint <= (offsetmemmap + int(size, 16)):

                    distormcounter = 0
                    blob = ''
                    for linedistorm in distorm:
                        try:
                            linedistorm = linedistorm.split(': ', 1)[1]
                            if hex(int(offset, 16)) in linedistorm:# or hex(int(line[5], 16)) in linedistorm:

                                if distormcounter >= 3:
                                    blob += distorm[distormcounter-3]
                                if distormcounter >= 2:
                                    blob += distorm[distormcounter-2]
                                if distormcounter >= 1:
                                    blob += distorm[distormcounter-1]
                                blob += distorm[distormcounter]
                                blob += distorm[distormcounter+1]
                                blob += distorm[distormcounter+2]
                                blob += distorm[distormcounter+3]
                        except:
                            pass

                        distormcounter += 1

                    string = Lobotomy.escchar(string)
                    # blob = Lobotomy.escchar(blob)
                    sql_counter += 1
                    sql_jobs.append((
                                    '{}'.format(line[0]),
                                    '{}'.format(line[1]),
                                    '{}'.format(line[2]),
                                    '{}'.format(line[3]),
                                    '{}'.format(line[4]),
                                    '{}'.format(line[5]),
                                    '{}'.format(hex(offsetint)),
                                    '{}'.format(string),
                                    '{}'.format(blob)
                                    ))

                    if len(sql_jobs) == int(bki):

                        save_sql(sql_jobs, plugin, database)
                        sql_jobs = []
                        Lobotomy.pl('Plugin: {} - Database: {} - lines processed: {} - pid: {}'.
                                    format(plugin, database, sql_counter, looking_pid))

    save_sql(sql_jobs, plugin, database)
    sql_jobs = []
    Lobotomy.pl('Plugin: {}, Database: {}, lines processed: {}'.
                format(plugin, database, sql_counter))

    Lobotomy.register_plugin('stop', database, plugin)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)


def save_sql(data, plugin, database):
    SQL_cmd = 'INSERT INTO {} (pid, `name`, virtual, physical, size, dumpfileoffset, offsetstrings, `string`, `blob`) values'.format(plugin)
    SQL_cmd += str(data).strip('[]')
    Lobotomy.exec_sql_query(SQL_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage: {} <databasename> <pid>".format(sys.argv[0])
    else:
        start(sys.argv[1], sys.argv[2])
