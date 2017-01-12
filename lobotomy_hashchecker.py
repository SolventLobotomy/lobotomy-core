__author__ = 'W2k8'

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "hashchecker"

DEBUG = False


def start(database):
    # case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    # command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)
    # Lobotomy.plugin_log('start', database, plugin, casedir, command)
    warnings = []
    Lobotomy.pl('Running Lobotomy - {}, please wait.'.format(plugin))
    # vollog = commands.getoutput(command)

    # Get a list of the plugins from the database
    tabledata = Lobotomy.get_databasedata('*', 'plugins', database)
    for row in tabledata:

        # row[1] = plugin name
        # Get the columns headers from the tables.

        md5tabledata = Lobotomy.get_databasecolumndata('{}'.format(row[1]), database)
        rowcounter = 0
        columnnames = []
        for md5row in md5tabledata:
            columnnames.append(md5row[0])
            # print row[1], md5row[0]
            if 'md5' in md5row[0]:

                # columnnames is a list with the names of the columns
                # Get the MD5 record from the table
                md5columndata = Lobotomy.get_databasedata('*', row[1], database)
                for md5columnrow in md5columndata:



                    sql_prefix = "bad_hashes where md5hash = '{}'".format(md5columnrow[rowcounter])
                    get_hash_from_db_tuple = Lobotomy.get_databasedata('md5hash', sql_prefix, 'lobotomy')
                    if get_hash_from_db_tuple:
                        # print 'MD5 Match: {}'.format(md5columnrow[rowcounter])

                        md5_sql_prefix = "{} where md5 = '{}'".format(row[1], md5columnrow[rowcounter])
                        md5_tablerow = Lobotomy.get_databasedata('*', md5_sql_prefix, database)

                        for real_md5_row in md5_tablerow:
                            counter = 0
                            md5_items = 'Warning! Bad Hash found in plugin: {}\n'.format(row[1])
                            for md5_item in real_md5_row:
                                # md5_items += ', {}\n'.format(str(md5_item))
                                try:
                                    md5_items += '{}: {}\n'.format(columnnames[counter], str(md5_item))
                                except IndexError: # list index out of range
                                    pass

                                # try:
                                #     print len(real_md5_row), len(columnnames)
                                #     print columnnames[counter], md5_item
                                # except:
                                #     pass
                                counter += 1
                                # try:
                                #     print row[1], columnnames[counter]
                                # except:
                                #     pass
                            warnings.append(md5_items)

                        # print
                        # db_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        # sql_line = "INSERT INTO bad_hashes VALUES (0, "
                        # sql_line = sql_line + "'{}', '{}', '{}', '0')".format(line, db_time, db_comment)



                #     print item
                # print md5row

            rowcounter += 1

    if len(warnings) > 0:
        Lobotomy.register_plugin('test', database, 'warnings')
        for warning in warnings:
            sql_cmd = "INSERT INTO warnings VALUES (0, '{}', '{}')".format(plugin, warning)
            Lobotomy.exec_sql_query(sql_cmd, database)

        Lobotomy.register_plugin('stop', database, 'warnings')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
