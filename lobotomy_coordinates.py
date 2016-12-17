__author__ = 'w2k8, iScripters'

#
# Date:             02 dec 2016
# Edited:           w2k8
# Detail:           Find coordinates in a memorydump


import sys
import main
import re

Lobotomy = main.Lobotomy()
plugin = "coordinates"

re_coord = re.compile('[0-9]{1,2}[.][0-9]{6},[0-9]{1,2}[.][0-9]{6}')


def start(database):
    command = 'Coordinates'
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Looking for Coordinates - {}, please wait.'.format(database))
    save_coord = []
    with open('{}-strings.txt'.format(imagename)) as f:
        for line in f:
            clean_line = line.strip()
            match_iterator = re_coord.finditer(clean_line)
            for match in match_iterator:
                match_token = match.group(0)
                # print '{},{}'.format(match_token, Lobotomy.escchar(clean_line))
                # save_coord.append('{},{}'.format(match_token, Lobotomy.escchar(clean_line)))
                sql_line = "INSERT INTO {} VALUES (".format(plugin)
                sql_line = sql_line + "0, '0', '{}', '{}')".\
                    format(match_token, Lobotomy.escchar(clean_line))
                Lobotomy.exec_sql_query(sql_line, database)

    Lobotomy.hashdata(database, plugin, save_coord)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_data(save_coord, database)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_data(log, database):
    for item in log:
        # coord, line = item
        print log[0], log[1]
        sql_line = "INSERT INTO {} VALUES (".format(plugin)
        sql_line = sql_line + "0, '0', '{}', '{}')".\
            format(item[0], item[1])
        Lobotomy.exec_sql_query(sql_line, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
