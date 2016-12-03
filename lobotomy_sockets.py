__author__ = 'w2k8, iScripters'

import sys
import os
import main
Lobotomy = main.Lobotomy()
plugin = "sockets"

DEBUG = False


def main(database):
    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    case_settings = Lobotomy.get_settings(database)
    imagename = case_settings["filepath"]
    imagetype = case_settings["profile"]
    casedir = case_settings["directory"]
    commando = []
    commando.append("vol.py -f " + imagename + " --profile=" + imagetype + " " + plugin + " > " + imagename + "-" + plugin + ".txt")
    commando.append("vol.py -f " + imagename + " --profile=" + imagetype + " " + plugin + " -P > " + imagename + "-" + plugin + "P.txt")

    for command in commando:
        if DEBUG:
            print "Write log: " + database + " ,Start: " + command
            print "Write log: " + casedir + " ,Start: " + command
        else:
            Lobotomy.write_to_main_log(database, " Start: " + command)
            Lobotomy.write_to_case_log(casedir, " Start: " + command)
            
        if DEBUG:
            print command
        else:
            os.system(command)
            
        if DEBUG:
            print "Write log: " + database + " ,Stop: " + command
            print "Write log: " + casedir + " ,Stop: " + command
        else:
            Lobotomy.write_to_main_log(database, " Stop : " + command)
            Lobotomy.write_to_case_log(casedir, " Stop : " + command)

        if DEBUG:
            print "Write log: (" + casedir + " ,Database: " + database + " Start:  running plugin: " + plugin + ")"
        else:
            Lobotomy.write_to_case_log(casedir,  "Database: " + database + " Start:  running plugin: " + plugin)

    linestarts = 0
    mem = ""
    
    try:
        with open(imagename + "-" + plugin + ".txt") as f:
            for line in f:
                if line.startswith("Offset(P)"):
                    mem = "physical"
                    memtype = "Offset(P)"
                if line.startswith("Offset(V)"):
                    mem = "virtual" 
                    memtype = "Offset(V)"
                if linestarts == 1 and memtype != "":
                    offset = line[0:10].strip(" ")
                    pid = line[11:19].strip(" ")
                    port = line[20:26].strip(" ")
                    proto = line[26:34].strip(" ")
                    protocol = line[34:49].strip(" ")
                    adress = line[50:66].strip(" ")
                    createtime = line[66:86]
                if mem != "" and linestarts == 1:
                    SQL_cmd = "INSERT INTO sockets VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(memtype, offset, pid, port, proto, protocol, adress, createtime)
                    if DEBUG:
                        print SQL_cmd
                    else:
                        Lobotomy.exec_sql_query(SQL_cmd, database)
                if line.startswith("----------"):
                    linestarts = 1

        linestarts = 0
        mem = ""

        with open(imagename + "-" + plugin + "P.txt") as f:
            for line in f:

                if line.startswith("Offset(P)"):
                    mem = "physical"
                    memtype = "Offset(P)"
                if line.startswith("Offset(V)"):
                    mem = "virtual" 
                    memtype = "Offset(V)"
                if linestarts == 1 and memtype != "":
                    offset = line[0:10].strip(" ")
                    pid = line[11:19].strip(" ")
                    port = line[20:26].strip(" ")
                    proto = line[26:34].strip(" ")
                    protocol = line[34:49].strip(" ")
                    adress = line[50:66].strip(" ")
                    createtime = line[66:86]
                if mem != "" and linestarts == 1:
                    SQL_cmd = "INSERT INTO sockets VALUES (0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(memtype, offset, pid, port, proto, protocol, adress, createtime)
                    if DEBUG:
                        print SQL_cmd
                    else:
                        Lobotomy.exec_sql_query(SQL_cmd, database)
                if line.startswith("----------"):
                    linestarts = 1
                    
    except IOError:
        print "IOError, file not found."
        if DEBUG:
            print "Debug mode is on: try creating a sample file."

    if DEBUG:
        print "Write log: (" + casedir + ", Database: " + database + " Stop:  running plugin: " + plugin + ")"
    else:
        Lobotomy.write_to_case_log(casedir, "Database: " + database + " Stop:  running plugin: " + plugin)
    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)

        
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: " + plugin + ".py <databasename>"
    else:
        main(sys.argv[1])
