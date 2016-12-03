__author__ = 'w2k8'

# Script version    0.2
# 18 nov 2015:      w2k8
# Plugin:           windows

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "windows"
plugintxt = 'http://volatility-labs.blogspot.nl/2012/09/movp-13-desktops-heaps-and-ransomware.html'


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

    # Parsing data
    print 'Parsing {} data...'.format(plugin)

    window_contect = window_handle_offset = window_handle = window_handle_name = blob = ''
    classatom = window_class = superclassatom = superwindow_class = ''
    pti = tid = tid_offset = ''
    ppi = process = pid = ''
    visible = xtop = xbottom = xright = xleft = ''
    style_flags = exstyle_flags = window_procedure = ''
    for line in voldata:
        if line.startswith('******'):
            window_contect = window_handle_offset = window_handle = window_handle_name = blob = ''
            classatom = window_class = superclassatom = superwindow_class = ''
            pti = tid = tid_offset = ''
            ppi = process = pid = ''
            visible = xtop = xbottom = xright = xleft = ''
            style_flags = exstyle_flags = window_procedure = ''
        if line.startswith('Window context:'):
            window_contect = line.split(': ')[1].replace('\\', '\\\\')
        if window_contect != '' and line.startswith('Window Handle:'):
            sql_data = 'INSERT INTO {} VALUES (0, '.format(plugin)
            sql_data += "'{}', '{}', '{}', '{}', ".format(window_contect, window_handle_offset, window_handle, window_handle_name)
            sql_data += "'{}', '{}', '{}', '{}', ".format(classatom, window_class, superclassatom, superwindow_class)
            sql_data += "'{}', '{}', '{}', ".format(pti, tid, tid_offset)
            sql_data += "'{}', '{}', '{}', '{}', ".format(ppi, process, pid, visible)
            sql_data += "'{}', '{}', '{}', '{}', ".format(xleft, xtop, xbottom, xright)
            sql_data += "'{}', '{}', '{}', '{}')".format(style_flags, exstyle_flags, window_procedure, blob)

            try:
                # print sql_data
                Lobotomy.exec_sql_query(sql_data, database)
            except:
                print line
                print 'SQL Error in {}, plugin: {}'.format(database, plugin)
                print 'SQL Error: {}'.format(sql_data)

            window_handle_offset = window_handle = window_handle_name = blob = ''
            classatom = window_class = superclassatom = superwindow_class = ''
            pti = tid = tid_offset = ''
            ppi = process = pid = ''
            visible = xtop = xbottom = xright = xleft = ''
            style_flags = exstyle_flags = window_procedure = ''

            window_handle = line.split(': ', 1)[1].split(' at ')[0]
            window_handle_offset = line.split(' at ')[1].split(', ')[0]
            if line.split('Name: ')[1] != '':
                window_handle_name = line.split('Name: ')[1].replace('\\', '\\\\').replace("'", "\\\'")
            else:
                window_handle_name = ''
        elif window_contect != '' and line.startswith('ClassAtom:'):
            classatom = line.split(': ', 1)[1].split(', ')[0]
            window_class = line.split(': ')[2]
        elif window_contect != '' and line.startswith('SuperClassAtom:'):
            superclassatom = line.split(': ', 1)[1].split(', ')[0]
            superwindow_class = line.split(': ')[2]
        elif window_contect != '' and line.startswith('pti:'):
            pti = line.split(': ', 1)[1].split(', ')[0]
            tid = line.split(': ')[2].split(' at ')[0]
            tid_offset = line.split(' at ')[1]
        elif window_contect != '' and line.startswith('ppi:'):
            ppi = line.split(': ', 1)[1].split(', ')[0]
            process = line.split(': ')[2].split(', ')[0]
            pid = line.split('Pid: ')[1]
        elif window_contect != '' and line.startswith('Visible:'):
            visible = line.split(': ')[1]
        elif window_contect != '' and line.startswith('Left:'):
            xleft = line.split(': ', 1)[1].split(', ')[0]
            xtop = line.split(': ')[2].split(', ')[0]
            xbottom= line.split(': ')[3].split(', ')[0]
            xright = line.split(': ')[4].split(', ')[0]
        elif window_contect != '' and line.startswith('Style Flags:'):
            style_flags = line.split(': ')[1]
        elif window_contect != '' and line.startswith('ExStyle Flags:'):
            exstyle_flags = line.split(': ')[1]
        elif window_contect != '' and line.startswith('Window procedure:'):
            window_procedure = line.split(': ')[1]
        elif window_contect != '' and line != '':
            blob += line + '\n'

    # save last line
    sql_data = 'INSERT INTO {} VALUES (0, '.format(plugin)
    sql_data += "'{}', '{}', '{}', '{}', ".format(window_contect, window_handle_offset, window_handle, window_handle_name)
    sql_data += "'{}', '{}', '{}', '{}', ".format(classatom, window_class, superclassatom, superwindow_class)
    sql_data += "'{}', '{}', '{}', ".format(pti, tid, tid_offset)
    sql_data += "'{}', '{}', '{}', '{}', ".format(ppi, process, pid, visible)
    sql_data += "'{}', '{}', '{}', '{}', ".format(xleft, xtop, xbottom, xright)
    sql_data += "'{}', '{}', '{}', '{}')".format(style_flags, exstyle_flags, window_procedure, blob)

    try:
        # print sql_data
        Lobotomy.exec_sql_query(sql_data, database)
    except:
        print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        print 'SQL Error: {}'.format(sql_data)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def check_database(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabledata = '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `Windowcontext` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_handle` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_handle_offset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_handle_name` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `classatom` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_class` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `superclassatom` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `superwindow_class` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pti` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `tid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `tid_offset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `ppi` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `process` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `visible` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `left` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `top` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `bottom` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `right` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `style_flags` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `exstyle_flags` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `window_procedure` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `data` blob,\
                  PRIMARY KEY (`id`)\
                 ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;'

    Lobotomy.testdatabase(database, plugin, tabledata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage:{}.py <databasename>".format(plugin)
    else:
        start(sys.argv[1])
