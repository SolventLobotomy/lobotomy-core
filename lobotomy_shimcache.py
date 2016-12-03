__author__ = 'w2k8'
#
# 04 jun 2016:      w2k8
# Plugin:           shimcache
# Detail:
# Plugin is testen on Windows XP Stuxnet.
# Plugin is testen on Windows 7 SP1 X64.

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "shimcache"

DEBUG = False


def start(database):

    # Register plugin start-time on the website
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)

    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    plugin_dir = Lobotomy.plugin_dir + 'plugins'
    log = ''

    command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)

    if DEBUG:
        print command
    else:
        print "Running Lobotomy - {}, please wait.".format(plugin)
        log = commands.getoutput(command)

    try:
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(log)
        f.close()
    except:
        pass

    parse_data(log, database)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def parse_data(log, database):
    items = log.split('\n')
    print 'Parsing {} data...'.format(plugin)

    write_sql = []
    column = []
    data = 0
    columnnr = 0

    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework'):
            tmp = line.split(' ')
            if line.startswith('----'):
                for l in range(len(tmp)):
                    column.append(len(tmp[l]))
                    columnnr = len(tmp)
                    data = 1
            line = line.replace('\\', '\\\\').replace('"', "'")
            if data == 1 and not line.startswith('---'):
                if columnnr == 3:
                    lm = line[0:column[0]].strip()
                    lu = line[column[0] + 1:column[0] + column[1] + 1].strip()
                    path = line[column[0] + column[1] + 2:].strip()
                    write_sql.append([lm, lu, path])
                if columnnr == 2:
                    lm = line[0:column[0]].strip()
                    path = line[column[0] + 1:].strip()
                    write_sql.append([lm, path])

    testdatabase(database, columnnr)

    if columnnr == 3:
        for lm, lu, path in write_sql:
            # Write SQL query to database
            sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}')".format(plugin, lm, lu, path)
            try:
                Lobotomy.exec_sql_query(sql_cmd, database)
            except:
                print 'SQL Error in {}, plugin: {}'.format(database, plugin)
                print 'SQL Error: {}'.format(sql_cmd)
    if columnnr == 2:
        for lm, path in write_sql:
            # Write SQL query to database
            sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}')".format(plugin, lm, path)
            try:
                Lobotomy.exec_sql_query(sql_cmd, database)
            except:
                print 'SQL Error in {}, plugin: {}'.format(database, plugin)
                print 'SQL Error: {}'.format(sql_cmd)
    return


def testdatabase(database, columnnrs):
    if Lobotomy.get_databasedata('*', plugin, database) is not None:
        print 'Sql table {} found. Dropping table {}'.format(plugin, plugin)
        Lobotomy.exec_sql_query("DROP TABLE IF EXISTS `{}`;".format(plugin), database)

        #if table not exist in database, create table
    if Lobotomy.get_databasedata('*', plugin, database) is None:
        if columnnrs == 3:
            # /*Table structure for table `shimcache` */
            print 'Sql table {} not found. Creating table {}.'.format(plugin, plugin)
            Lobotomy.exec_sql_query("CREATE TABLE `{}` (\
                  `id` int(11) NOT NULL AUTO_INCREMENT,\
                  `lastmodified` varchar(32) NOT NULL,\
                  `lastupdate` varchar(32) NOT NULL,\
                  `path` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;".format(plugin), database)
        else:
            # /*Table structure for table `shimcache` */
            print 'Sql table {} not found. Creating table {}.'.format(plugin, plugin)
            Lobotomy.exec_sql_query("CREATE TABLE `{}` (\
                  `id` int(11) NOT NULL AUTO_INCREMENT,\
                  `lastmodified` varchar(32) NOT NULL,\
                  `path` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;".format(plugin), database)

    # truncate: DELETE from tabelname
    # Autoincrement: ALTER TABLE tablename auto_increment=1

    # Truncate current table
    sql_cmd = "DELETE from {}".format(plugin)
    try:
        Lobotomy.exec_sql_query(sql_cmd, database)
    except:
        print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        print 'SQL Error: {}'.format(sql_cmd)

    # Set Autoincrement to 1
    sql_cmd = "ALTER TABLE {} auto_increment=1".format(plugin)
    try:
        Lobotomy.exec_sql_query(sql_cmd, database)
    except:
        print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        print 'SQL Error: {}'.format(sql_cmd)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {}.py <databasename>".format(plugin)
    else:
        start(sys.argv[1])
