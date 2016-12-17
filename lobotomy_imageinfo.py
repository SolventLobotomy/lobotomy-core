#!/usr/bin/env python
__author__ = 'w2k8, iScripters'
#
# 26 nov 2015:      w2k8
# Plugin:           imageinfo
# Detail:           New version of imageinfo.
#                   Script can also converts an hiberfile to a memorydump

import re
import sys
import commands
import main
import collections

plugin = 'imageinfo'
Lobotomy = main.Lobotomy()

global windows_systems
windows_systems = (['Windows XP:WinXP', 'Windows 7:Win7', 'Windows 8:Win8', 'Windows 2008:Win2008',
                    'Windows 2012:Win2012', 'Windows 10:Win10'])
imageinfoprofile = win = ''


def imageinfo(database):
    global imagename
    global servicepack
    settings = Lobotomy.get_settings(database)
    imagename = settings["filepath"]

    Lobotomy.plugin_start(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 1)
    Lobotomy.write_to_main_log(database, "Starting 'imageinfo' plugin...")
    Lobotomy.write_to_case_log(settings['directory'], "Starting 'imageinfo' plugin...")

    command = 'vol.py -f {} imageinfo'.format(imagename)
    imagetype = ''

    Lobotomy.write_to_case_log(settings['directory'], "Executing command imageinfo")
    Lobotomy.write_to_case_log(settings['directory'], "EXEC: {}".format(command))

    print 'Running imageinfo'
    data = exec_command(command)

    Lobotomy.write_to_case_log(settings['directory'], "Command imageinfo executed")
    servicepack = profiles = ''

    print 'Parsing {} data...'.format(plugin)

    imagetype, profiles, servicepack = parsing_data(data, database)

    if imagetype == 'hyberfil':
        profiles = hiberfil(database, profiles)

    imageinfoprofile = test_imagename(profiles)

    if imageinfoprofile != '' and imageinfoprofile in profiles:
        print 'match: {}'.format(imageinfoprofile)
        Lobotomy.write_to_case_log(settings['directory'], "Possible match: {}. Inserting in database..".format(imageinfoprofile))
        Lobotomy.write_to_main_log(database, "Imageinfo found a possible match: {}. Inserting in database..".format(imageinfoprofile))
        Lobotomy.exec_sql_query("UPDATE settings SET profile='{}'".format(imageinfoprofile), database)

    # Begin change
    else:

        for x in profiles.strip().split(','):
            sp = 'SP{}'.format(servicepack)
            if sp in x:
                x = x.replace(' ', '')
                Lobotomy.write_to_case_log(settings['directory'], "Possible match: {}. Inserting in database..".format(x))
                Lobotomy.write_to_main_log(database, "Imageinfo found a possible match: {}. Inserting in database..".format(x))
                Lobotomy.exec_sql_query("UPDATE settings SET profile='{}'".format(x), database)

    # end change

    Lobotomy.write_to_case_log(settings['directory'], "Stopping 'imageinfo' plugin...")
    Lobotomy.write_to_main_log(database, "Stopping 'imageinfo' plugin...")
    Lobotomy.plugin_stop(plugin, database)
    Lobotomy.plugin_pct(plugin, database, 100)


def exec_command(command):
    log = ''
    log = commands.getoutput(command)

    try:
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(log)
        f.close()
    except:
        pass

    data = log.split('\n')
    return data


def hiberfil(database, profiles):
    hiberfilename = '{}.mem'.format(imagename.split('.')[0])
    command = 'vol.py -f {} --profile={} imagecopy -O {}'.format(imagename, profiles, hiberfilename)
    print 'Hiberfil detected. Converting hiberfil to memorydump.'
    log = exec_command(command)
    command = 'vol.py -f {} imageinfo'.format(hiberfilename)
    print 'Running imageinfo.'
    log = exec_command(command)
    print 'calculating new MD5 hash'
    md5 = Lobotomy.md5Checksum(hiberfilename)
    print 'calculating new SHA hash'
    filesha256, filemtime, fileatime, filectime, filesize = Lobotomy.sha256checksum(hiberfilename)

    Lobotomy.exec_sql_query("UPDATE settings SET filepath='{}'".format(hiberfilename), database)
    Lobotomy.exec_sql_query("UPDATE settings SET filename='{}'".format(hiberfilename.split('/')[-1]), database)
    Lobotomy.exec_sql_query("UPDATE settings SET profile='{}'".format(profiles), database)
    Lobotomy.exec_sql_query("UPDATE settings SET `md5hash`='{}'".format(md5), database)
    Lobotomy.exec_sql_query("UPDATE settings SET `sha256hash`='{}'".format(filesha256), database)

    imagetype, profiles_tmp, servicepack = parsing_data(log, database)
    return profiles


def test_imagename(profiles):
    imageinfoprofile = ''
    # commandstrings = 'strings {} > {}-strings.txt'.format(imagename, imagename)
    # Dumping strings with offset so it can be re-used in other plugins.
    commandstrings = 'strings -a -td {} > {}-strings.txt'.format(imagename, imagename)
    print 'Dumping strings from {}'.format(imagename)
    commands.getoutput(commandstrings)

    win = ''
    wincounter = []
    with open('{}-strings.txt'.format(imagename)) as fs:
        for line in fs:
            for winsys in windows_systems:
                if winsys.split(':')[0] in line:
                    # Need to build a counter for the matches, no break. With a break the first match wil taken.
                    wincounter.append(winsys.split(':')[0])

    counter = collections.Counter(wincounter)

    # trying to match volatility imageinfo with output from strings.
    print 'Strings from memorydump most used Windows version: {}, counted {} times'.\
        format(counter.most_common()[0][0], counter.most_common()[0][1])

    for winsys in windows_systems:
        if winsys.split(':')[0] == counter.most_common()[0][0]:
            win = winsys.split(':')[1]
            windows = winsys.split(':')[0]
            break

    # try to get the Windows version from image info.pass

    for profile in profiles.split(', '):
        if win in profile:
            # sp = 'SP{}'.format(servicepack)
            # if sp in profile:
            imageinfoprofile = profile

    print 'Selected profile based on Imageinfo and Strings: {}'.format(imageinfoprofile)

    return imageinfoprofile


def parsing_data(data, database):
    servicepack = imagetype = profiles = SQL_cmd = image_datetime = image_local_datetime = ''
    for line in data:
        if not line.startswith("Determining") and line != "\n" and not line.startswith('Volatility Foundation'):
            try:
                SQL_cmd = "INSERT INTO imageinfo VALUES (0, '{}', '{}')".format(
                    line.split(' : ')[0].strip("  "), line.split(' : ')[1].strip('\n'))
                Lobotomy.exec_sql_query(SQL_cmd, database)
            except IndexError: # list index out of range
                print line

        if 'WindowsHiberFileSpace32' in line:
            imagetype = 'hyberfil'
        if 'Suggested Profile(s)' in line:
            if 'Instantiated with ' in line:
                profiles = line.split('Instantiated with ')[1].strip(')')
                Lobotomy.exec_sql_query("UPDATE settings SET profile='{}'".format(profiles), database)
            else:
                profiles = line.split(':')[1].strip().strip('\n')
                profiles = re.sub(r'\([^)]*\)', '', profiles)
                Lobotomy.exec_sql_query("UPDATE settings SET profile='{}'".format(profiles), database)
        if 'Image Type (Service Pack)' in line:
            servicepack = line.split(':')[1].strip().strip('\n')
        if 'Image date and time' in line:
            image_datetime = line.split(':')[1].strip().strip('\n')
            Lobotomy.exec_sql_query("UPDATE settings SET `image_datetime`='{}'".format(image_datetime), database)
        if 'Image local date and time' in line:
            image_local_datetime = line.split(':')[1].strip().strip('\n')
            Lobotomy.exec_sql_query("UPDATE settings SET `image_local_datetime`='{}'".format(image_local_datetime), database)

    return imagetype, profiles, servicepack


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: imageinfo.py [Database]"
    else:
        imageinfo(sys.argv[1])
