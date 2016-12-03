__author__ = 'w2k8'
#
# 04 jun 2016:      w2k8
# Plugin:           DriverIrp
# Detail:

import sys
import commands
import main
Lobotomy = main.Lobotomy()

plugin = "driverirp"

DEBUG = False


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py --plugins={} -f {} --profile={} {}'.format(plugin_dir, imagename, imagetype, plugin)
    Lobotomy.plugin_log('start', database, plugin, casedir, command)

    Lobotomy.pl('Running Volatility - {}, please wait.'.format(plugin))
    vollog = commands.getoutput(command)

    Lobotomy.save_log(imagename, plugin, vollog)
    Lobotomy.hashdata(database, plugin, vollog)

    Lobotomy.plugin_log('stop', database, plugin, casedir, command)
    Lobotomy.pl('Parsing data from plugin: {}...'.format(plugin))

    parse_voldata(vollog, database)

    Lobotomy.register_plugin('stop', database, plugin)


def parse_voldata(log, database):
    items = log.split('\n')

    c = []
    data = 0
    irp = 0
    write_sql = []

    drivername = driverstart = driversize = driverstartio = nr = irpname = offset = name = ''

    warnings = []
    warningscounter = 0
    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework') and not line.startswith('*** Failed'):
            if line.startswith('----') and irp == 1:
                irp = 0

            if irp == 1:
                nr = line[:5]
                irpname = line[5:42]
                offset = line[42:53]
                name = line[53:]
                write_sql.append([drivername, driverstart, driversize, driverstartio, nr, irpname, offset, name])

            if line.startswith('DriverName:') and irp != 1:
                drivername = line.split(': ')[1]
            if line.startswith('DriverStart:') and irp != 1:
                driverstart = line.split(': ')[1]
            if line.startswith('DriverSize:') and irp != 1:
                driversize = line.split(': ')[1]
            if line.startswith('DriverStartIo') and irp != 1:
                driverstartio = line.split(': ')[1]
                irp = 1

    for drivername, driverstart, driversize, driverstartio, nr, irpname, offset, name in write_sql:
    
        # Write SQL query to database
        sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".\
                  format(plugin, drivername, driverstart, driversize, driverstartio, nr, irpname, offset, name)
        Lobotomy.exec_sql_query(sql_cmd, database)

    return

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
