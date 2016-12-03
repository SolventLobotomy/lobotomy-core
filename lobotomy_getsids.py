__author__ = 'w2k8, iScripters'


import sys
import main
import commands

Lobotomy = main.Lobotomy()
plugin = 'getsids'

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

    for line in items:
        if not line.startswith('Volatility Foundation Volatility Framework'):
            a, b = line.split(": ")
            proc, pid = a.split(" (")
            try:
                sid, user = b.split(" (")  # S-1-5-6 (Service), of S-1-2-0 (Local (Users ...))
                comment = " "
            except ValueError:
                try:
                    sid, user, comment = b.split(" (")  # S-1-2-0 (Local (Users ...)) of S-1-5-90-0
                except ValueError:
                    sid = b.split(" (")  # S-1-5-90-0
                    user = ""
                    comment = ""

            try:
                pid = pid.strip(")")
            except AttributeError:
                pass
            try:
                sid = sid.strip()
            except AttributeError:
                sid = sid[0].strip("\n")
            try:
                user = user.strip("\n").strip(")")
            except AttributeError:
                pass
            try:
                comment = comment.strip("\n").strip(")")
            except AttributeError:
                pass
            SQL_cmd = "INSERT INTO getsids VALUES (0, '{}', '{}', '{}', '{}', '{}')".format(proc, pid, sid, user, comment)
            Lobotomy.exec_sql_query(SQL_cmd, database)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} <databasename>".format(sys.argv[0])
    else:
        start(sys.argv[1])
