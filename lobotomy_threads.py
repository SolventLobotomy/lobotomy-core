__author__ = 'w2k8, iScripters'
# Date:             24 jul 2016
# Edited:           w2k8
# Detail:           Created new plugin for lobotomy
#

import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = "threads"


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py -f {} --profile={} {} --output=greptext'.format(imagename, imagetype, plugin)
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
    data = log.split('\n')
    sql_data = []
    lp = []
    for line in data:

        if line.startswith('>|'):
            tmp, Offset, PID, TID, Tags, Create_Time, Exit_Time, Owning_Process, Attached_Process, State, \
            State_Reason, Base_Priority, Priority, TEB, Start_Address, Owner_Name, Win32_Start_Address,\
            Win32_Thread, Cross_Thread_Flags, EIP, EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, ErrCode, SegCS,\
            SegSS, SegDS, SegES, SegGS, SegFS, EFlags, dr0, dr1, dr2, dr3, dr6, dr7, SSDT, Entry_Number,\
            Descriptor_Service_Table, Hook_Number, Function_Name, Function_Address, Module_Name,\
            Disassembly = line.split('|')

            sql_data.append((
                            Offset, PID, TID, Tags, Create_Time, Exit_Time, Owning_Process,
                            Attached_Process, State, State_Reason, Base_Priority, Priority, TEB, Start_Address,
                            Owner_Name, Win32_Start_Address, Win32_Thread, Cross_Thread_Flags, EIP, EAX, EBX,
                            ECX, EDX, ESI, EDI, ESP, EBP, ErrCode, SegCS, SegSS, SegDS, SegES, SegGS, SegFS,
                            EFlags, dr0, dr1, dr2, dr3, dr6, dr7, SSDT, Entry_Number, Descriptor_Service_Table,
                            Hook_Number, Function_Name, Function_Address, Module_Name, Disassembly
                            ))

    sql_prefix = "INSERT INTO {} VALUES (0".format(plugin)
    for sql_line in sql_data:
        sql_cmd = ''
        for item in sql_line:
            # sql_line[5] and [6] are datetime formats.
            if item == sql_line[5]:
                item = Lobotomy.tz_data(database, plugin, sql_line[5])
            if item == sql_line[6]:
                item = Lobotomy.tz_data(database, plugin, sql_line[6])

            # print len(sql_line)
            sql_cmd += ",'{}'".format(item)
        sql_cmd = '{}{})'.format(sql_prefix, sql_cmd)
        Lobotomy.exec_sql_query(sql_cmd, database)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
