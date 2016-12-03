__author__ = 'w2k8, iScripters'
#
# 08 mrt 2015:      w2k8
# Plugin:           Malfind, Needed for Threatindex
#
# Date:             11-09-2015

import sys
import commands
import main
Lobotomy = main.Lobotomy()
plugin = "malfind"

DEBUG = False


def main(database):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    command = "vol.py -f " + imagename + " --profile=" + imagetype + " " + plugin

    if DEBUG:
        print "Write log: " + database + ", Start: " + command
        print "Write log: " + casedir + ", Start: " + command
    else:
        Lobotomy.write_to_main_log(database, " Start: " + command)
        Lobotomy.write_to_case_log(casedir, " Start: " + command)

    if DEBUG:
        print command
    else:
        print "Running Volatility -", plugin, ", please wait."
        vollog = ""
        status, vollog = commands.getstatusoutput(command)

    if DEBUG:
        print "Write log: " + database + " Stop: " + command
        print "Write log: " + casedir + " Stop: " + command
    else:
        Lobotomy.write_to_case_log(casedir, " Stop : " + command)

    if DEBUG:
        print "Write log: (" + casedir + ", Database: " + database + " Start: Parsing volatility output: " + plugin + ")"
    else:
        Lobotomy.write_to_case_log(casedir, " Database: " + database + " Start: Parsing volatility output: " + plugin)

    try:
        f = open(imagename + '-' + plugin + '.txt', 'w')
        f.write(vollog)
        f.close()
    except:
        pass

    items = vollog.split('\n')
    print 'Parsing ' + plugin + ' data...'

    count = 0
    counter = 0
    for line in items:
        if line.startswith('Process:'):
            counter += 1

    flags = ''
    body = ''
    header = ''
    read4lines = 4
    pct = 0
    for line in items:
        test = line.split(' ')
        if line.startswith('Process:'):
            count += 1
            pct = str(float(1.0 * count / counter) * 100).split(".")[0]
            process = test[1]
            pid = test[3]
            address = test[5].strip('\n')
        if line.startswith('Vad Tag:'):
            vadtag = line[8:12].strip(' ')
            protection = line[25:].strip('\n')
        if flags != '':
            if read4lines == 0 and line != '':
                body += str(line) + '\n'
            if read4lines != 0 and line != '':
                header += str(line) + '\n'
                read4lines -= 1
            if body != '' and header != '' and flags != '' and line == '':
                # end of MZ, next line
                sql_line = "INSERT INTO " + plugin + " VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
                    format(process, pid, address, vadtag, protection, flags, header, body)
                try:
                    Lobotomy.exec_sql_query(sql_line, database)
                except:
                    print 'SQL Error in ', database, 'plugin: ', plugin
                    print 'SQL Error: ',  sql_line
                    Lobotomy.write_to_case_log(casedir, "Database: " + database + " Error:  running plugin: " + plugin)
                    Lobotomy.write_to_case_log(casedir, "Database: " + database + 'SQL line: ' + sql_line)

                # reset
                body = ''
                header = ''
                flags = ''
                read4lines = 4

        if line.startswith('Flags:'):
            flags = line

        try:
            if pct != pcttmp:
                print "plugin: " + plugin + " - Database: " + database + " - pct done: " + str(pct)
                Lobotomy.plugin_pct(plugin, database, pct)
        except:
            pass
        pcttmp = pct

    if DEBUG:
        print "Write log: (" + casedir + " ,Database: " + database + " Stop:  running plugin: " + plugin + ")"
    else:
        Lobotomy.write_to_case_log(casedir, "Database: " + database + " Stop:  running plugin: " + plugin)
    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def save_sql(sql_line, database):
    try:
        Lobotomy.exec_sql_query(sql_line, database)
    except:
        print 'SQL Error in ', database, 'plugin: ', plugin
        print 'SQL Error: ',  sql_line


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        main(sys.argv[1])
