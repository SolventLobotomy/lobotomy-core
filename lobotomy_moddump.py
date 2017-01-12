__author__ = 'w2k8, iScripters'

#
# 11 aug 2015:      w2k8
# Plugin:           procdump

import sys
import main
import commands
Lobotomy = main.Lobotomy()
plugin = "moddump"

DEBUG = False


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    Lobotomy.plugin_start('exifinfo', database)
    Lobotomy.plugin_stop('exifinfo', database)

    dumpdir = "{}/moddump".format(casedir)

    try:
        log = commands.getoutput("mkdir {}".format(dumpdir))
        Lobotomy.write_to_main_log(database, "mkdir: {}".format(log))
        Lobotomy.write_to_case_log(casedir, "mkdir: {}".format(log))
    except:
        pass

    command = "vol.py -f {} --profile={} {} --dump-dir={}".format(imagename, imagetype, plugin, dumpdir)
    # command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)
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


def parse_voldata(log, database, dumpdir):
    counter = 0
    result = []
    part = []
    pcttmp = 0
    linePointer = 0
    lastLinePointer = 0
    pointers = []
    md5 = "0"
    sha256 = '0'
    filename = ''
    fullfilename = ''

    items = log.split('\n')

    for line in items:
        if counter == 2:
            for x in line.split(' '):
                pointers.append(len(x)+1)
            pointers.pop(len(pointers)-1)
            pointers.append(255)
        if counter > 2:
            for x in range(len(pointers)): # Loop through columns
                item = pointers[x] 
                lastLinePointer += item
                part.append(line[linePointer:lastLinePointer].strip('\n').strip(' '))
                linePointer += item
            linePointer = 0
            lastLinePointer = 0
            if DEBUG:
                pass
            result.append(part)
        counter += 1
        part = []

    count = 0
    counter = len(result)
    for listitem in result:
        count += 1
        pct = str(float(1.0 * count / counter) * 100).split(".")[0]

        sql_line = "INSERT INTO {} VALUES (0, ".format(plugin)
        for item in listitem:
            item = Lobotomy.escchar(item)
            sql_line += "'{}',".format(item)
            if item == listitem[2] and item.startswith("OK:"):
                md5 = Lobotomy.md5Checksum("{}/{}".format(dumpdir, listitem[2].strip("OK: ")))
                sha256 = Lobotomy.sha256checksum("{}/{}".format(dumpdir, listitem[2].strip("OK: ")))[0]
                filename = listitem[2].strip("OK: ")
                fullfilename = "{}/{}".format(dumpdir, listitem[2].strip("OK: "))

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
                    pass
            else:
                md5 = "0"
                sha256 = '0'
                filename = ''
                fullfilename = ''

        sql_line += "'{}','{}','{}','{}')".format(md5, sha256, filename, fullfilename)
        Lobotomy.exec_sql_query(sql_line, database)

        try:
            if pct != pcttmp:
                Lobotomy.pl("plugin: {} - Database: {} - pct done: {}".format(plugin, database, str(pct)))
                Lobotomy.plugin_pct(plugin, database, pct)
        except:
            pass
        pcttmp = pct


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {}.py <databasename>".format(plugin)
    else:
        start(sys.argv[1])
