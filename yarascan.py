__author__ = 'w2k8, iScripters'

import sys
import main
import commands
import os

Lobotomy = main.Lobotomy()
plugin = "yarascan"

DEBUG = False


def start(database, folder):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    yara_rules = Lobotomy.yararules + 'index.yara'
    sql_prefix = "INSERT INTO yarascan VALUES (0, "
    counter = 0
    count = 0
    sql_line = ''
    pct = 0
    test_table(plugin, database)
    try:
        f = open(imagename + '-' + plugin + '.txt', 'w')
        f.write('')
        f.close()
    except:
        pass

    command = "yara {} {}".format(yara_rules, database)
    if DEBUG:
        print "Write log: " + database + ", Start: " + command
        print "Write log: " + casedir + ", Start: " + command
    else:
        Lobotomy.write_to_main_log(database, " Start: " + command)
        Lobotomy.write_to_case_log(casedir, " Start: " + command)

    if folder == '':

        for subdir, dirs, files in os.walk(casedir):
            for folders in dirs:
                for subdir1, dirs1, files1 in os.walk(subdir + '/' + folders):
                    for file in files1:
                        counter += 1

        for subdir, dirs, files in os.walk(casedir):
            for folders in dirs:
                for subdir1, dirs1, files1 in os.walk(subdir + '/' + folders):
                    print "Running yarascan on folder: " + subdir1
                    for file in files1:
                        filename = ''
                        offset = ''
                        description = ''
                        string = ''
                        yara = ''
                        yara_description = ''
                        count = count +1
                        filename = os.path.join(subdir1, file)
                        command = "yara {} {} -m -s -w".format(yara_rules, filename)
                        # Yara -w: disable warnings
                        # Yara -m: print metadata.
                        # Yara -s: print matching strings.
                        if DEBUG:
                            print command
                        else:
                            log = ""
                            status, log = commands.getstatusoutput(command)
                        try:
                            f = open(imagename + '-' + plugin + '.txt', 'a')
                            f.write(log)
                            if log != '':
                                f.write('\n')
                            f.close()
                        except:
                            pass

                        try:
                            pct = str(float(1.0 * count / counter) * 99).split(".")[0]
                            print "Yarascan - Percentage done: ", pct
                        except:
                            pass
                        print "Yarascan - Files to go: " + str(counter) + " from " + str(count)
                        print "Yarascan - Current filename:", filename
                        if log != '':
                            for item in log.split('\n'):
                                if filename in item:
                                    #count += 1
                                    Lobotomy.escchar(item)
                                    yara = item.split('[')[0]
                                    if 'description' in item:
                                        start = int(item.find('description')+13)
                                        yara_description = item[start:].split('"')[0]
                                        filename = "/" + item.split('/', 1)[1].replace('//', '/')
                                else:
                                    Lobotomy.escchar(item)
                                    a = item.split(':')
                                    try:
                                        offset = a[0]
                                    except:
                                        offset = ''
                                    try:
                                        description = a[1]
                                    except:
                                        description = ''
                                    try:
                                        string = a[2][1:]
                                    except:
                                        string = ''
                                    try:
                                        sql_line = sql_prefix + "'{}', '{}', '{}', '{}', '{}', '{}', '')".format(filename,\
                                                offset, description, string, yara, yara_description)# + ")")#[:-1]
                                        Lobotomy.exec_sql_query(sql_line, database)
                                        Lobotomy.plugin_pct(plugin, database, pct)
                                    except:

                                        print 'Error sql query: ' + sql_line + " - " + database

    command = "yara {} {} -m -s -w".format(yara_rules, imagename)
    # Yara -w: disable warnings
    # Yara -m: print metadata.
    # Yara -s: print matching strings.
    print "Running Yarascan on memorydump: {}".format(imagename)

    log = ""
    status, log = commands.getstatusoutput(command)
    try:
        f = open(imagename + '-' + plugin + '.txt', 'a')
        f.write(log)
        if log != '':
            f.write('\n')
        f.close()
    except:
        pass

    filename = imagename
    yara = ''
    yara_description = ''

    # todo:
    # parse logfile for memorydump (variable log) and convert hex to dec for volatility.
    # try to find the pid in memorydump for the yara output
    # grep the offset fist, then the string. split the :
    # change yara table. add two columns, 1 for pid, 1 for offset.
    # 0x1e6b02c3:$code1: E8 5C 78 F0 FF DD D8
    # 0x163bb800:$str2: -GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32
    # >>> print (0x163bb800)
    # 373012480
    #  >>> print (0x1cbdf600)
    # 482211328

    # Parsing yara logs and getting offset and string.
    yara_to_pid = ''
    for item in log.split('\n'):
        if '[description=' not in item:
            # get the hex value and convert it to dec
            if yara_to_pid != '':
                try:
                    yara_to_pid += '\n{} {}'.format((int(item.split(':')[0], 16)), item.split(':')[2])
                except ValueError:
                    pass # Need to fix ValueError
                        # Traceback (most recent call last):
                        #   File "/srv/lobotomy/lob_scripts/yarascan.py", line 281, in <module>
                        #     start(sys.argv[1], folder)
                        #   File "/srv/lobotomy/lob_scripts/yarascan.py", line 183, in start
                        #     yara_to_pid += '\n{} {}'.format((int(item.split(':')[0], 16)), item.split(':')[2])
                        # ValueError: invalid literal for int() with base 16: 'ccrewMiniasp [author="AlienVault Labs",info="CommentCrew-threat-apt1"] '

            if yara_to_pid == '':
                yara_to_pid += '{} {}'.format((int(item.split(':')[0], 16)), item.split(':')[2])

    # writing to logfile and use volatility to get the pid.
    if yara_to_pid != '':
        f = open('{}-yara_to_pid.txt'.format(imagename), 'w')
        f.write(yara_to_pid)
        f.close()
    command = 'vol.py -f {} --profile={} strings -s {}-yara_to_pid.txt'.format(imagename, imagetype, imagename)
    yaralog = commands.getoutput(command)
    #print log

    #print yara_to_pid
            # pid = item.split(':')[0]
            # pid_offset = item.split(':')[2]

    yaralog = yaralog.split('\n')
    if log != '':
        for item in log.split('\n'):
            pid = pid_offset = ''
            if filename in item:

                yara = item.split('[')[0]
                if 'description' in item:
                    start = int(item.find('description')+13)
                    yara_description = item[start:].split('"')[0]
                    filename = "/" + item.split('/', 1)[1].replace('//', '/')
            else:
                Lobotomy.escchar(item)
                a = item.split(':')
                try:
                    offset = a[0]
                except:
                    offset = ''
                try:
                    description = a[1]
                except:
                    description = ''
                try:
                    string = a[2][1:]
                except:
                    string = ''

                for yaraoffset in yaralog:
                    if not yaraoffset.startswith('Volatility Foundation'):
                        # print yaraoffset
                        # print int(offset, 16), int(yaraoffset.split(' ', 1)[0])
                        if int(offset, 16) == int(yaraoffset.split(' ', 1)[0]):#not in item:
                            pid_offset = yaraoffset.split('[')[1].split(']')[0]
                try:
                    sql_line = sql_prefix + "'{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(filename,\
                            offset, description, string, yara, yara_description, pid_offset)
                    Lobotomy.exec_sql_query(sql_line, database)
                    Lobotomy.plugin_pct(plugin, database, pct)
                except:
                    print 'Error sql query: {} - {}'.format(sql_line, database)


    Lobotomy.write_to_case_log(casedir, " Stop : " + command)
    Lobotomy.write_to_case_log(casedir, " Database: " + database + " Start: Parsing Yara output: " + plugin)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def test_table(plugin, database):
    """if table exist in database, drop it """
    if Lobotomy.get_databasedata('*', plugin, database) is not None:
        print 'Sql table found. Dropping table {}'.format(plugin)
        Lobotomy.exec_sql_query("DROP TABLE IF EXISTS `{}`;".format(plugin), database)

    """
    if table not exist in database, create table
    /*Table structure for table `yarascan` */
    """
    if Lobotomy.get_databasedata('*', plugin, database) is None:
        print 'Sql table not found. Creating table {}'.format(plugin)
        Lobotomy.exec_sql_query("CREATE TABLE `{}` (\
                      `id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                      `filename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                      `offset` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                      `description` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                      `string` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                      `yara` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                      `yara_description` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                      `pid:offset` varchar(1024) COLLATE utf8_bin DEFAULT NULL,\
                      PRIMARY KEY (`id`)\
                    ) ENGINE=InnoDB AUTO_INCREMENT=1608 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;".format(plugin), database)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: {}.py <database> <folder>".format(plugin)
    else:
        folder = ''
        try:
            folder = sys.argv[2]
        except:
            pass
        start(sys.argv[1], folder)

