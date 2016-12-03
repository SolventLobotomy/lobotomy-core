__author__ = 'w2k8, iScripters'
#
# 08 aug 2015:  w2k8
# Aanpasing van de huidige versie.
#
# 12 aug 2015:  w2k8
# Fixed parsing error in handles when data is '------'.

# Need to fix!
# vol.py -f sality.vmem pstree
# Volatility Foundation Volatility Framework 2.4
# Name                                                  Pid   PPid   Thds   Hnds Time
# -------------------------------------------------- ------ ------ ------ ------ ----
#  0xff2ab020:?$`d???u?Q[D                        30...2 46...0 41...0 ------ -
#  0x810b1660:System                                      4      0     58    190 1970-01-01 00:00:00 UTC+0000


import sys
import commands
import main
from dateutil.parser import parse
Lobotomy = main.Lobotomy()
plugin = "pstree"

DEBUG = False


def main(database):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    command = "vol.py -f " + imagename + " --profile=" + imagetype + " " + plugin + " -v"

    if DEBUG:
        print "Write log: " + database + ", Start: " + command
        print "Write log: " + casedir + ", Start: " + command
    else:
        Lobotomy.write_to_main_log(database, " Start: " + command)
        Lobotomy.write_to_case_log(casedir, " Start: " + command)
        
    if DEBUG:
        print command
    else:
        print "Running Volatility - PSTree including option 'v', please wait."
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

    save_sql = 0
    for line in items:
        if line.startswith('Name') or line.startswith('-----'):
            if line.startswith('-----'):
                lenline = line.split(' ')
        else:
            test = line.split(' ')
            if test[0].startswith('.') or test[1].startswith('0x') and 'UTC' in line:
                # Save SQl before we overwrite things with new values
                if save_sql == 1:
                    SQL_cmd = "INSERT INTO pstree VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', " \
                              "'{}', '{}')".format(dots, offset, name, pid, ppid, thrds, hnds, plugintime, audit, cmd, path)
                    if DEBUG:
                        print SQL_cmd
                    else:
                        Lobotomy.exec_sql_query(SQL_cmd, database)
                    save_sql = 0
                audit = ''
                cmd = ''
                path = ''
                dots = len(test[0])
                offset = test[1].split(':')[0]
                name = test[1].split(':')[1]
                pid = line[len(lenline[0]):len(lenline[0] + lenline[1]) + 1].strip(' ')
                ppid = line[len(lenline[0] + lenline[1]) + 1:len(lenline[0] + lenline[1] + lenline[2]) + 2].strip(' ')
                thrds = line[len(lenline[0] + lenline[1] + lenline[2]) + 2:len(lenline[0] + lenline[1] +
                                lenline[2] + lenline[3]) + 3].strip(' ')
                hnds = line[len(lenline[0] + lenline[1] + lenline[2] + lenline[3]) + 3:len(lenline[0] + lenline[1] +
                                lenline[2] + lenline[3] + lenline[4]) + 4].strip(' ')
                if hnds.startswith('------'):
                    hnds = '0'
                plugintime = line[len(lenline[0] + lenline[1] + lenline[2] + lenline[3] + lenline[4]) + 4:]
                plugintime = parse(plugintime).strftime("%Y-%m-%d %H:%M:%S")
            else:
                line = line.replace('\\', '\\\\')
                if line.strip(' ').startswith('audit:'):
                    audit = line.split('audit: ')[1]
                    save_sql = 1
                if line.strip(' ').startswith('cmd:'):
                    cmd = line.split('cmd: ')[1]
                    save_sql = 1
                if line.strip(' ').startswith('path:'):
                    path = line.split('path: ')[1]
                    save_sql = 1
    # Save the last SQl line to the database
    try:
        if save_sql == 1:
            SQL_cmd = "INSERT INTO pstree VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
                format(dots, offset, name, pid, ppid, thrds, hnds, plugintime, audit, cmd, path)
            if DEBUG:
                print SQL_cmd
            else:
                Lobotomy.exec_sql_query(SQL_cmd, database)
            save_sql = 0
    except:
        pass

    if DEBUG:
        print "Write log: (" + casedir + " ,Database: " + database + " Stop:  running plugin: " + plugin + ")"
    else:
        Lobotomy.write_to_case_log(casedir, "Database: " + database + " Stop:  running plugin: " + plugin)
    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        main(sys.argv[1])
