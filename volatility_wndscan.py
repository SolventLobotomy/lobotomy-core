__author__ = 'w2k8, iScripters'

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "wndscan"
plugintxt = 'http://volatility-labs.blogspot.nl/2012/09/movp-12-window-stations-and-clipboard.html'

DEBUG = False


def start(database):
    # Register plugin start-time on the website
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    check_database(database)

    command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)

    print "Running Volatility - {}, please wait.".format(plugin)
    log = ""
    status, log = commands.getstatusoutput(command)

    try:
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(log)
        f.close()
    except:
        pass

    voldata = log.split('\n')

    # Truncate current table wndscan
    sql_cmd = "DELETE from {}".format(plugin)
    try:
        Lobotomy.exec_sql_query(sql_cmd, database)
    except:
        print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        print 'SQL Error: {}'.format(sql_cmd)

    # Set Autoincrement to 1, table wndscan
    sql_cmd = "ALTER TABLE {} auto_increment=1".format(plugin)
    try:
        Lobotomy.exec_sql_query(sql_cmd, database)
    except:
        print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        print 'SQL Error: {}'.format(sql_cmd)

    # Parsing data
    print 'Parsing {} data...'.format(plugin)

    WindowStation = name = valuenext = sessionid = atomtable = interactive = ptiDrawingClipboard = ''
    desktops = spwndClipOpen = spwndClipViewer = cNumClipFormats = iClipSerialNumber = pClipBase = Formats = ''
    spwndoffset = spwndpid = spwndexe = ''
    for line in voldata:
        if not line.startswith('******'):
            if line.startswith('WindowStation:'):
                WindowStation = line.split(': ', 1)[1].split(',', 1)[0]
                if 'Name:' in line:
                    name = line.split(', ')[1].split(': ')[1]
                if 'Next:' in line:
                    valuenext = line.split(': ')[3]
            if line.startswith('SessionId:'):
                sessionid = line.split(': ')[1].split(', ')[0]
                if 'AtomTable:' in line:
                    atomtable = line.split(': ')[1].split(',')[0]
                if 'Interactive:' in line:
                    interactive = line.split(': ')[3]
            if line.startswith('Desktops:'):
                desktops = line.split(': ')[1]
            if line.startswith('ptiDrawingClipboard:'):
                # need to get pid and thd, i dont have seen any dump file with a pid and thd yet.
                # for now we grab the whole line.
                ptiDrawingClipboard = line.split(': ')[1]
            if line.startswith('spwndClipOpen:'):
                spwndClipOpen = line.split(': ')[1].split(', ')[0]
                if 'spwndClipViewer:' in line:
                    spwndClipViewer = line.split(': ')[2]
                    spwndoffset = spwndpid = spwndexe = ''
                    try:
                        spwndoffset = spwndClipViewer.split(' ')[0]
                        spwndpid = spwndClipViewer.split(' ')[1]
                        spwndexe = spwndClipViewer.split(' ', 2)[2]
                    except:
                        pass
            if line.startswith('cNumClipFormats:'):
                cNumClipFormats = line.split(': ')[1].split(', ')[0]
                if 'iClipSerialNumber:' in line:
                    iClipSerialNumber = line.split(': ')[2]
            if line.startswith('pClipBase:'):
                pClipBase = line.split(': ')[1].split(', ')[0]
                if 'Formats:' in line:
                    Formats = line.split(': ')[2]
        if line.startswith('******') and WindowStation != '':
            # save SQL
            sql_data = 'INSERT INTO {} VALUES (0, '.format(plugin)
            sql_data += "'{}', '{}', '{}', '{}', ".format(WindowStation, name, valuenext, sessionid)
            sql_data += "'{}', '{}', '{}', '{}', ".format(atomtable, interactive, desktops, ptiDrawingClipboard)
            sql_data += "'{}', ".format(spwndClipOpen)
            sql_data += "'{}', '{}', '{}', '{}', ".format(cNumClipFormats, iClipSerialNumber, pClipBase, Formats)
            sql_data += "'{}', '{}', '{}', '{}')".format(spwndClipViewer, spwndoffset,  spwndpid, spwndexe)

            try:
                #print sql_cmd
                Lobotomy.exec_sql_query(sql_data, database)
            except:
                print 'SQL Error in {}, plugin: {}'.format(database, plugin)
                print 'SQL Error: {}'.format(sql_cmd)

            WindowStation = name = valuenext = sessionid = atomtable = interactive = ptiDrawingClipboard = ''
            desktops = spwndClipOpen = spwndClipViewer = cNumClipFormats = iClipSerialNumber = pClipBase = Formats = ''
            spwndoffset = spwndpid = spwndexe = ''

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def check_database(database):

    # if table not exist in database, create table
    if Lobotomy.get_databasedata('*', plugin, database) is None:
        print 'Sql table not found. Creating table {}'.format(plugin)
        Lobotomy.exec_sql_query("CREATE TABLE IF NOT EXISTS `wndscan` (\
                              `id` int(12) NOT NULL AUTO_INCREMENT,\
                              `WindowStation` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `name` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `next` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `sessionid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `atomtable` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `interactive` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `desktops` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `ptiDrawingClipboard` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `spwndClipOpen` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `cNumClipFormats` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `iClipSerialNumber` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `pClipBase` varchar(512) COLLATE utf8_bin DEFAULT NULL,\
                              `Formats` varchar(512) COLLATE utf8_bin DEFAULT NULL,\
                              `spwndClipViewer` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `spwndoffset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `spwndpid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `spwndprocess` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              PRIMARY KEY (`id`)\
                            ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;", database)

    else:
        # Truncate current table
        sql_cmd = "DELETE from {}".format(plugin)
        try:
            Lobotomy.exec_sql_query(sql_cmd, database)
        except:
            print 'SQL Error in {}, plugin: {}'.format(database, plugin)
            print 'SQL Error: {}'.format(sql_cmd)

        # Set Autoincrement to 1 for table
        sql_cmd = "ALTER TABLE {} auto_increment=1".format(plugin)
        try:
            Lobotomy.exec_sql_query(sql_cmd, database)
        except:
            print 'SQL Error in {}, plugin: {}'.format(database, plugin)
            print 'SQL Error: {}'.format(sql_cmd)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        start(sys.argv[1])
