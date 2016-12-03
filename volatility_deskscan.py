__author__ = 'w2k8'

# 18 nov 2015:      w2k8
# Plugin:           deskscan

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "deskscan"
plugintxt = 'http://volatility-labs.blogspot.nl/2012/09/movp-13-desktops-heaps-and-ransomware.html'


def start(database):
    # if table not exist in database, create table
    if Lobotomy.get_databasedata('*', plugin, database) is None:
        print 'Sql table not found. Creating table {}'.format(plugin)
        Lobotomy.exec_sql_query("CREATE TABLE IF NOT EXISTS `deskscan` (\
                              `id` int(12) NOT NULL AUTO_INCREMENT,\
                              `desktop` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `name` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `next` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `sessionid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `desktopinfo` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `fshooks` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `spwnd` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `windows` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `heap` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `size` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `base` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `limit` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `desktoplist` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `pid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `ppid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              `proccessname` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                              PRIMARY KEY (`id`)\
                            ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;", database)

    # Register plugin start-time on the website
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]

    command = 'vol.py -f {} --profile={} {} -v'.format(imagename, imagetype, plugin)

    print "Running Volatility - {}, please wait.".format(plugin)
    log = ""
    status, log = commands.getstatusoutput(command)

    try:
        f = open(imagename + '-' + plugin + '.txt', 'w')
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
        print 'SQL Error in ', database, 'plugin: ', plugin
        print 'SQL Error: ',  sql_cmd

    # Set Autoincrement to 1, table wndscan
    sql_cmd = "ALTER TABLE {} auto_increment=1".format(plugin)
    try:
        Lobotomy.exec_sql_query(sql_cmd, database)
    except:
        print 'SQL Error in ', database, 'plugin: ', plugin
        print 'SQL Error: ',  sql_cmd

    # Parsing data
    print 'Parsing {} data...'.format(plugin)

    datahash = []
    desktop = name = valuenext = sessionid = desktopinfo = fshooks = spwnd = windows = heap = size = base = limit = ''
    desktoplist = proccessppid = proccesspid = proccessname = ''
    for line in voldata:
        if not line.startswith('******'):
            if line.startswith('Desktop:'):
                desktop = line.split(': ', 1)[1].split(',', 1)[0]
                if 'Name:' in line:
                    name = line.split(', ')[1].split(': ')[1].replace('\\', '\\\\')
                if 'Next:' in line:
                    valuenext = line.split(': ')[3]
            if line.startswith('SessionId:'):
                sessionid = line.split(': ')[1].split(', ')[0]
                if 'DesktopInfo:' in line:
                    desktopinfo = line.split(': ')[2].split(', ')[0]
                if 'fsHooks:' in line:
                    fshooks = line.split(': ')[3]
            if line.startswith('spwnd:'):
                spwnd = line.split(': ')[1].split(', ')[0]
                if 'Windows:' in line:
                    windows = line.split(': ')[2]
            if line.startswith('Heap:'):
                heap = line.split(': ')[1].split(', ')[0]
                if 'Size:' in line:
                    size = line.split(': ')[2].split(', ')[0]
                if 'Base:' in line:
                    base = line.split(': ')[3].split(', ')[0]
                if 'Limit:' in line:
                    limit = line.split(': ')[4]
            try:
                if heap != '' and int(line.split(' ')[1]):
                    desktoplist = line
                    proccessppid = desktoplist.split('(')[1].split(')')[0].split(' ')[-1]
                    proccesspid = desktoplist.split('(')[1].split(')')[0].split(' ')[-3]
                    proccessname = desktoplist.split('(')[1].split(')')[0].split(proccesspid)[0]
            except ValueError:
                pass

            if heap != '':
                # save SQL
                sql_data = 'INSERT INTO {} VALUES (0, '.format(plugin)
                sql_data += "'{}', '{}', '{}', '{}', ".format(desktop, name, valuenext, sessionid)
                sql_data += "'{}', '{}', '{}', '{}', ".format(desktopinfo, fshooks, spwnd, windows)
                sql_data += "'{}', '{}', '{}', '{}', ".format(heap, size, base, limit)
                sql_data += "'{}', '{}', '{}', '{}')".format(desktoplist, proccesspid, proccessppid, proccessname)

                data = ''
                data += "'{}', '{}', '{}', '{}', ".format(desktop, name, valuenext, sessionid)
                data += "'{}', '{}', '{}', '{}', ".format(desktopinfo, fshooks, spwnd, windows)
                data += "'{}', '{}', '{}', '{}'".format(heap, size, base, limit)

                datahash.append(data)

                try:
                    # print sql_data
                    Lobotomy.exec_sql_query(sql_data, database)
                except:
                    print 'SQL Error in ', database, 'plugin: ', plugin
                    print 'SQL Error: ',  sql_data
                desktoplist = proccessppid = proccesspid = proccessname = ''

        if line.startswith('******') and heap != '':
            desktop = name = valuenext = sessionid = desktopinfo = fshooks = spwnd = windows = heap = ''
            size = base = limit = desktoplist = proccessppid = proccesspid = proccessname = ''

    #print datahash
    tablehash = Lobotomy.hash_table(datahash, database)
    sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
    Lobotomy.exec_sql_query(sql_data, database)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        start(sys.argv[1])
