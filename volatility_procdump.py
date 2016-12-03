__author__ = 'w2k8, iScripters'
#
# Script version    0.1
# Plugin version:   0.1
# 11 aug 2015:      w2k8
# Plugin:           Procdump
# Edit:             02 okt 2015
# Detail:           Procdump, incl slackspace

import sys
import commands
import main

Lobotomy = main.Lobotomy()
plugin = "procdump"


def main(database):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    dumpdir = casedir + '/' + plugin

    command = []
    command.append('mkdir {}'.format(dumpdir))
    command.append('mkdir {}-slack'.format(dumpdir))
    for line in command:
        try:
            log = ""
            status, log = commands.getstatusoutput(line)
        except:
            pass

    command = []
    # Dumping process
    command.append('vol.py -f {} --profile={} {} --dump-dir={}'.format(imagename, imagetype, plugin, dumpdir))
    # Dumping process include memory slackspace
    command.append('vol.py -f {} --profile={} {} -m --dump-dir={}-slack'.format(imagename, imagetype, plugin, dumpdir))

    #command = "vol.py -f " + imagename + " --profile=" + imagetype + " " + plugin + " --dump-dir=" + dumpdir

    for line in command:
        log = ''
        pluginoption = ''
        if line[-5:] == 'slack':
            pluginoption = '-m'
        print "Running Volatility - {} {} please wait.".format(plugin, pluginoption)
        status, log = commands.getstatusoutput(line)
        savelog(imagename, plugin, log, pluginoption)
        parselog(log, pluginoption, dumpdir, database)

    Lobotomy.write_to_main_log(database, " Stop : {} ".format(command))
    Lobotomy.write_to_case_log(casedir, "Database: {} Stop: Parsing volatility output: {}".format(database, plugin+pluginoption))
    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def savelog(imagename, plugin, log, pluginoption):
    try:
        f = open(imagename + '-' + plugin + pluginoption + '.txt', 'w')
        f.write(log)
        f.close()
    except:
        pass


def parselog(log, pluginoption, dumpdir, database):
    pct = 0
    pcttmp = 0
    counter = 0
    result = []
    part = []
    linePointer = 0
    lastLinePointer = 0
    pointers = []
    md5 = "0"
    md5filename = ''
    fullfilename = ''

    items = log.split('\n')
    if pluginoption == '':
        print 'Parsing {}...'.format(plugin)
    else:
        print 'Parsing {} with option {}...'.format(plugin, pluginoption)

    for line in items:
        if counter == 2:
            for x in line.split(' '):
                pointers.append(len(x)+1)
            pointers.pop(len(pointers)-1)
            pointers.append(255)
        if counter > 2:
            for x in range(len(pointers)): # Loop aantal kolommen
                """Build a list of all the files"""

                item = pointers[x]
                lastLinePointer += item
                part.append(line[linePointer:lastLinePointer].strip('\n').strip(' '))
                linePointer += item
            linePointer = 0
            lastLinePointer = 0
            result.append(part)
        counter += 1
        part = []

    count = 0
    counter = len(result)
    for listitem in result:
        count += 1
        pct = str(float(1.0 * count / counter) * 99).split(".")[0]

        sql_line = "INSERT INTO " + plugin + " VALUES (0, "
        for item in listitem:
            item = item.replace('\\', '\\\\')
            if item == listitem[3] and item.startswith("OK:") and pluginoption == '-m':
                sql_line = sql_line + "'{}',".format('Incl slack: ' + item)
            else:
                sql_line = sql_line + "'{}',".format(item)
            if item == listitem[3] and item.startswith("OK:"):
                if pluginoption == '':
                    md5 = Lobotomy.md5Checksum(dumpdir + "/" + listitem[3].strip("OK: "))
                    md5filename = listitem[3].strip("OK: ")
                    fullfilename = dumpdir + "/" + listitem[3].strip("OK: ")
                elif pluginoption == '-m':
                    md5 = Lobotomy.md5Checksum(dumpdir + "-slack/" + listitem[3].strip("OK: "))
                    md5filename = listitem[3].strip("OK: ")
                    fullfilename = dumpdir + "-slack/" + listitem[3].strip("OK: ")

                # Exiftool routine
                # moved routine due to the msg: 'Error: PEB at ... is unavailable (possibly due to paging)'
                try:
                    command = "exiftool " + fullfilename
                    status, log = commands.getstatusoutput(command)
                    exif_SQL_cmd = "INSERT INTO exifinfo VALUES (0, '{}', '{}')".format(fullfilename, log)
                    Lobotomy.exec_sql_query(exif_SQL_cmd, database)
                except:
                    print "Error parse-ing file: " + fullfilename
                    exif_SQL_cmd = "INSERT INTO exifinfo VALUES (0, '{}', '{}')".format(fullfilename, 'Parse error')
                    Lobotomy.exec_sql_query(exif_SQL_cmd, database)
                    pass
            else:
                md5 = "0"
                md5filename = ''
                fullfilename = ''
        sql_line = sql_line + "'{}','{}','{}')".format(md5, md5filename, fullfilename)
        Lobotomy.exec_sql_query(sql_line, database)

        try:
            if pct != pcttmp:
                print "plugin: {} - Database: {} - pct done: {}".format(plugin, database, str(pct))
                Lobotomy.plugin_pct(plugin, database, pct)
        except:
            pass
        pcttmp = pct
    print "plugin: {} - Database: {} - pct done: {}".format(plugin, database, str(100))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        main(sys.argv[1])
