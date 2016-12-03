__author__ = 'w2k8, iScripters'
#
# Script version    0.8
# Plugin version:   1
# 11 aug 2015:      w2k8
# Plugin:           Netscan
# Edit:             16 okt 2015
# Detail:           Get the networkconnections from a memorydump
# Detail:           Needed for Report function
# Edit:             13 jul 2016
# Detail:           Change parsing process for IPv6
#                   Tested with Windows 7 SP1 x64

import sys
import main
from cStringIO import StringIO

Lobotomy = main.Lobotomy()

plugin = "netscan"

DEBUG = False


def start(database):

    import volatility.conf as conf
    import volatility.registry as registry
    registry.PluginImporter()
    import volatility.commands as commands
    import volatility.addrspace as addrspace
    config = conf.ConfObject()
    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)
    # import volatility.debug as debug
    # import volatility.win32 as win32
    # import volatility.obj as obj
    # import volatility.utils as utils
    import volatility.plugins.netscan as netscan

    config.parse_options()
    config.PROFILE = ''
    config.LOCATION = ''

    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    case = database
    config.PROFILE = imagetype
    config.LOCATION = 'file://{}'.format(imagename)

    # Check if Profile is supported
    if imagetype.startswith('WinXP' or 'mac_' or 'linux_'):
        print '{} is not supported for {}'.format(plugin, imagetype)
        exit()

    testdatabase(database)

    # Register plugin start-time on the website
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)

    print 'Running {}, please wait...'.format(plugin)

    # Get the data and redirect it to volnetscan
    p = netscan.Netscan(config)
    old_stdout = sys.stdout
    sys.stdout = voldata = StringIO()
    p.render_text(sys.stdout, p.calculate())
    sys.stdout = old_stdout

    # Writing log to casefolder
    try:
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(str(voldata.getvalue()))
        f.close()
    except:
        pass

    voldata = voldata.getvalue().split('\n')

    # Parsing data
    print 'Parsing {} data...'.format(plugin)
    for line in voldata:
        lenladdress = 0
        lenfaddress = 0
        offsetp = proto = laddress = faddress = state = pid = owner = created = ''

        if line != '' and not line.startswith('Offset'):
            offsetp = line[0:19].strip(' ') # Offset {0:<18}
            proto = line[19:28].strip(' ') # Proto {1:<8}
            laddress = line[28:59].strip(' ') # Local Address {2:<30}
            faddress = line[59:80].strip(' ') # Foreing Address {3:<20}

            if 'v6' in proto: # IPv6
                laddress = line[28:].split(' ')[0]
                # if len(laddress) >= 30:
                #     lenladdress = len(laddress)
                # else:
                #     lenladdress = 0

                if lenladdress == 0: # length of local address is not larger then 30
                    faddress = line[59:].split(' ')[0] # Foreing Address {3:<20}
                    lenfaddress = len(faddress)
                else:  # length of local address is larger then 30
                    faddress = line[28 + lenladdress:].split(' ')[0]
                    lenfaddress = len(faddress)

            if lenfaddress >= 20 or lenladdress >= 20:
                state = line[80 + (lenfaddress - 20) + lenladdress:97 + (lenfaddress - 20) + lenladdress].strip(' ') # State {4:<16}
                pid = line[97 + (lenfaddress - 20) + lenladdress:106 + (lenfaddress - 20) + lenladdress].strip(' ') # Pid {5:<8}
                owner = line[106 + (lenfaddress - 20) + lenladdress:121 + (lenfaddress - 20) + lenladdress] # Owner {6:<14}
                created = line[121 + (lenfaddress - 20) + lenladdress:] # Created {7}
            else:
                state = line[80:97].strip(' ') # State {4:<16}
                pid = line[97:106].strip(' ') # Pid {5:<8}
                owner = line[106:121] # Owner {6:<14}
                created = line[121:] # Created {7}

            if pid.startswith('--'):
                pid = '-1'

            # Build SQL String
            sql_cmd = "INSERT INTO {} VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(plugin,
                                                    offsetp, proto, laddress, faddress, state, pid, owner, created)
            try:
                Lobotomy.exec_sql_query(sql_cmd, database)
            except:
                print 'SQL Error in {} plugin: {}'.format(database, plugin)
                print 'SQL Error: {}'.format(sql_cmd)

    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def testdatabase(database):
    """ if table not exist in database, create table , otherwise drop table and recreate table"""
    tabeldata = '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `proto` varchar(12) COLLATE utf8_bin DEFAULT NULL,\
                  `localaddress` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `foreignadress` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `state` varchar(20) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` int(8) DEFAULT NULL,\
                  `owner` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `createtime` varchar(32) COLLATE utf8_bin  NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;'

    Lobotomy.testdatabase(database, plugin, tabeldata)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {}.py <databasename>".format(plugin)
    else:
        start(sys.argv[1])
