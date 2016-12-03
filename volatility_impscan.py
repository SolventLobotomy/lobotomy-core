__author__ = 'w2k8, iScripters'
#
# 11 aug 2015:      w2k8
# Plugin:           impscan
# Edit:             14 sep 2015
# Detail:           Needed for Threatindex
# Update:           11 dec 2015
#                   exports idc file for ida


import sys
import commands
import main
Lobotomy = main.Lobotomy()
plugin = "impscan"

DEBUG = False


def start(database):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    # command = "vol.py -f {} --profile={} {}".format(imagename, imagetype, plugin)

    Lobotomy.write_to_case_log(casedir, " Database: {} Start: Parsing volatility output: {}".format(database, plugin))
    data_ldrmod = ''

    try:
        data_ldrmod = Lobotomy.get_databasedata('pid,process,base,inload,ininit,inmem,mappedpath,loadpathpath,'
                                                'loadpathprocess, initpathpath, initpathprocess, mempathpath,'
                                                'mempathprocess', 'ldrmodules_v', database)
    except:
        print 'Fail to get data from database'

    try:
        data_impscan = []
        for line_ldrmodules in data_ldrmod:
            ldr_pid, ldr_process, ldr_base, ldr_inload, ldr_ininit, ldr_inmem, ldr_mappedpath, ldr_loadpathpath, \
            ldr_loadpathprocess, ldr_initpathpath, ldr_initpathprocess, ldr_mempathpath, ldr_mempathprocess = line_ldrmodules
            if ldr_mappedpath == '' and ldr_ininit == 'False':
                print '\n***********************************'
                print 'Possible unlinked Dll found'
                print 'Empty Ldr_Mappedpath and Ldr_ininit is False, getting imports from process.'
                print '***********************************'
                print 'Process         : ' + ldr_process
                print 'Base            : ' + ldr_base
                print 'Pid Ldrmodules  : ' + str(ldr_pid)
                tmp = ldr_process, ldr_pid, ldr_base
                data_impscan.append(tmp)
    except:
        data_impscan = ''
        print 'error parsing items'

    datahash = []
    for process, pid, base in data_impscan:
        command = "vol.py -f {} --profile={} {} -b {} -p {}".format(imagename, imagetype, plugin, base, pid)
        Lobotomy.write_to_main_log(database, " Start: " + command)
        Lobotomy.write_to_case_log(casedir, " Start: " + command)

        print "Running Volatility - {}, please wait.".format(plugin)
        print command
        status, vollog = commands.getstatusoutput(command)

        print 'Dumping idc file: {}-{}-{}.idc'.format(imagename, pid, base)
        command = "vol.py -f {} --profile={} {} -b {} -p {} --output=idc --output-file={}-{}-{}.idc".format(
            imagename, imagetype, plugin, base, pid, imagename, pid, base)
        print command
        log = commands.getoutput(command)

        Lobotomy.write_to_case_log(casedir, " Stop : " + command)

        try:
            f = open(imagename + '-' + plugin + '-' + pid + '-' + base + '.txt', 'w')
            f.write(vollog)
            f.close()
        except:
            pass

        print 'parsing items'
        for item in vollog.split('\n'):
            if not item.startswith('Volatility'):
                if not item.startswith('IAT'):
                    if not item.startswith('---'):
                        test = item.split(' ')
                        imptmp = ''
                        for a in test:
                            if a != '':
                                imptmp += a + ' '
                        tmp = process + ' ' + str(pid) + ' ' + str(base) + ' ' + str(imptmp[:-1])
                        datahash.append(process + ', ' + str(base) + ', ' + str(imptmp[:-1]).replace(' ', ', '))

                        sql_cmd = ''
                        line = tmp.split(' ')
                        for sql_item in line:
                            sql_cmd += ", '{}'".format(sql_item)

                        sqlq = "INSERT INTO " + plugin + " VALUES (0" + sql_cmd + ")"
                        try:
                            Lobotomy.exec_sql_query(sqlq, database)
                        except:
                            print 'SQL Error in ', database, 'plugin: ', plugin
                            print 'SQL Error: ',  sqlq

    Lobotomy.write_to_case_log(casedir, "Database: " + database + " Stop:  running plugin: " + plugin)

    # print datahash
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
