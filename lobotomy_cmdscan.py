__author__ = 'w2k8, iScripters'



import sys
import commands
import main
Lobotomy = main.Lobotomy()
plugin = "cmdscan"

DEBUG = False


def start(database):
    case_settings, imagename, imagetype, casedir, plugin_dir = Lobotomy.register_plugin('start', database, plugin)
    command = 'vol.py -f {} --profile={} {}'.format(imagename, imagetype, plugin)
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
    pid = ''
    CommandProcess = ''
    CommandHistory = ''
    Application = ''
    Flags = ''
    CommandCount = ''
    LastAdded = ''
    LastDisplayed = ''
    FirstCommand = ''
    CommandCountMax = ''
    ProcessHandle = ''
    cmd = ''

    for line in items:
        line = Lobotomy.escchar(line)
        # line = line.replace('\\', '\\\\').replace("'", "\"").replace('"', '\"')
        if line.startswith('*****'):
            pid = ''
            CommandProcess = ''
            CommandHistory = ''
            Application = ''
            Flags = ''
            CommandCount = ''
            LastAdded = ''
            LastDisplayed = ''
            FirstCommand = ''
            CommandCountMax = ''
            ProcessHandle = ''
            cmd = ''
        else:
            test = line.split(': ')
            if line.startswith('CommandProcess'):
                CommandProcess = test[1][:-4]
                pid = test[2]
            if line.startswith('CommandHistory'):
                CommandHistory = test[1].split(' ')[0]
                Application = test[2][:-6]
                Flags = test[-1]
            if line.startswith('CommandCount'):
                CommandCount = line.split(' ')[1]
                LastAdded = line.split(' ')[3]
                LastDisplayed = line.split(' ')[5]
            if line.startswith('FirstCommand'):
                FirstCommand = line.split(' ')[1]
                CommandCountMax  = line.split(' ')[3]
            if line.startswith('ProcessHandle'):
                ProcessHandle = test[1]
            if line.startswith('Cmd'):
                cmd = line
                sql_line = "INSERT INTO cmdscan VALUES ("
                sql_line = sql_line + "0, '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format\
                    (pid, CommandProcess, CommandHistory, Application, Flags, CommandCount, LastAdded, LastDisplayed,
                    FirstCommand, CommandCountMax, ProcessHandle, cmd)
                Lobotomy.exec_sql_query(sql_line, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
