__author__ = 'w2k8, iScripters'

#
# Date:             02 dec 2016
# Edited:           w2k8
# Detail:           Find coordinates in a memorydump
# Version:          1.0

import sys
import main
import re
import commands

Lobotomy = main.Lobotomy()
plugin = "coordinates"

re_coord = re.compile('[0-9]{1,2}[.][0-9]{6},[0-9]{1,2}[.][0-9]{6}')

# 1. Get the coordinates from a memdump.
# 2. Get the offset from the coordinates
# 3. Get the pid from the coordinates with the offset.
# 4. Get the processname from the pid.
# 5. Now we have the process name belong to the coordinates


def start(database):
    global imagename
    global imagetype
    command = 'Coordinates'
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    save_coord = []
    volstring = ''
    Lobotomy.pl('Reading strings file')

# 1. Get the coordinates from a memdump.
    with open('{}-strings.txt'.format(imagename)) as f:
        for line in f:
            # clean_line = line.strip()
            clean_line = line
            match_iterator = re_coord.finditer(clean_line)
            for match in match_iterator:
                match_token = match.group(0)

# 2a. Get the offset from the coordinates
                offset = line.split(' ', 1)[0]
                try:
                    a, clean_line1 = clean_line.split(' ', 1)
                    save_coord.append((match_token, offset, 0, 0, clean_line1))
                    volstring += '{}'.format(line)
                except ValueError:
                    Lobotomy.pl('Error parsing line: \n{}'.format(line))

# 1/2b. save the log.

    f = open('{}-{}_raw.txt'.format(imagename, plugin), 'w')
    f.write(volstring)
    f.close()

# 3. Get the pid from the coordinates with the offset.
    Lobotomy.pl('Running volatility strings to match offset with pid')
    command = ('vol.py -f {} --profile={} strings -s {}-{}_raw.txt'.format(imagename, imagetype, imagename, plugin))
    log = commands.getoutput(command)

    log = log.split('\n')

# 4. Get the processname from the pid.
    # Getting data from table psxview
    data_psxview = Lobotomy.get_databasedata('name,pid', 'psxview', database)

    dummy1 = []

# 5. Now we have the process name belong to the coordinates
# Match the pid, processname and coordinates together.

    for line in log:
        if not line.startswith('Volatility'):
            offset, pid, linea = line.split(' ', 2)

            for test in enumerate(save_coord):
                # if linea == test[1][4] and offset == test[1][1]:# results 143:182 == linea: # Test for string valua
                if linea in test[1][4] and offset == test[1][1]:# results 349:182 == linea: # Test for string valua
                    processname = 'None'
                    for pidname, pidpid in data_psxview:
                        if pid.split(':')[0].strip('[]') == pidpid:
                            processname = pidname
                    dummy1.append((test[1][0], test[1][1], pid.split(':')[0].strip('[]'), processname, test[1][4]))

# Lets put everything in the database.
    for item in dummy1:
        sql_line = "INSERT INTO {} VALUES (".format(plugin)
        sql_line = sql_line + "0, '0', '{}', '{}', '{}', '{}', '{}')".\
            format(item[0], item[1], item[2], item[3], item[4])
        Lobotomy.exec_sql_query(sql_line, database)

    f = open('{}-{}_pid.txt'.format(imagename, plugin), 'w')
    for line in log:
        f.write(str(line))
    f.close()

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)

    Lobotomy.register_plugin('stop', database, plugin)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
