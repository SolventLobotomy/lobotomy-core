__author__ = 'w2k8, iScripters'

#
# Date:             09-07-2015
# Edited:           w2k8
#
# Date:             20 jul 2016
# Edited:           w2k8
# Detail:           Fixed an issue when parsing a string with ' or "
#

import sys
import commands
import main

Lobotomy = main.Lobotomy()
plugin = "svcscan"

DEBUG = False


def run_main(database):
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
        print "Running Volatility, plugin: " + plugin + ", please wait."
        log = ""
        status, log = commands.getstatusoutput(command)
    if DEBUG:
        print "Write log: " + database + " Stop: " + command
        print "Write log: " + casedir + " Stop: " + command
    else:
        Lobotomy.write_to_case_log(casedir, " Stop : " + command)

    try:
        f = open(imagename + '-' + plugin + '.txt', 'w')
        f.write(log)
        f.close()
    except:
        pass

    if DEBUG:
        print "Write log: (" + casedir + ", Database: " + database + " Start: Parsing " + plugin + " output: " + plugin + ")"
    else:
        Lobotomy.write_to_case_log(casedir, " Database: " + database + " Start: Parsing " + plugin + " output: " + plugin)

    sql_prefix = "INSERT INTO " + plugin + " VALUES (0, "
    sql_line = ''
    counter = 0
    count = 0
    pct = 0
    db_offset = ''
    db_order = ''
    db_start = ''
    db_procces_id = ''
    db_service_name = ''
    db_display_name = ''
    db_service_type = ''
    db_service_state = ''
    db_binary_path = ''

    try:
        logcounter = 0
        for loglines in log.split('\n'):
            if folder in loglines:
                logcounter += 1
    except:
        pass

    items = log.split('\n')
    print 'Parsing ' + plugin + ' data...'

    for item in items:
        item = item.replace("'", "\"").replace('"', '\"')
        try:
            pct = str(float(1.0 * count / logcounter) * 99).split(".")[0]
        except:
            pass
        count += 1

        if item.startswith('Offset:'):
            try:
                db_offset = item.split(' ', 1)[1]
            except:
                pass
        if item.startswith('Order:'):
            try:
                db_order = item.split(' ', 1)[1]
            except:
                pass
        if item.startswith('Start:'):
            try:
                db_start = item.split(' ', 1)[1]
            except:
                pass
        if item.startswith('Process ID:'):
            try:
                db_procces_id = item.split(':', 1)[1][1:]
            except:
                pass
        if item.startswith('Service Name:'):
            try:
                db_service_name = item.split(':', 1)[1][1:]
            except:
                pass
        if item.startswith('Display Name:'):
            try:
                db_display_name = item.split(':', 1)[1][1:]
            except:
                pass
        if item.startswith('Service Type:'):
            try:
                db_service_type = item.split(':', 1)[1][1:]
            except:
                pass
        if item.startswith('Service State:'):
            try:
                db_service_state = item.split(':', 1)[1][1:]
            except:
                pass
        if item.startswith('Binary Path:'):
            try:
                db_binary_path = item.split(':', 1)[1][1:].replace('\\', '\\\\')
            except:
                pass

            sql_line = sql_prefix + "'{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}'".\
                format(
                db_offset,
                db_order,
                db_start,
                db_procces_id,
                db_service_name,
                db_display_name,
                db_service_type,
                db_service_state,
                db_binary_path + "')")[:-1]

            try:
                Lobotomy.exec_sql_query(sql_line, database)
                Lobotomy.plugin_pct(plugin, database, pct)
            except:
                print 'Error sql query: ' + sql_line + " - " + database

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        run_main(sys.argv[1])
