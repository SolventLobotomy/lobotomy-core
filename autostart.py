#!/usr/bin/env python
#
# Date:             14-05-2015
# Edited:           w2k8
# Plugin:           autostart

import sys
import main
import time

Lobotomy = main.Lobotomy()


def autostart(database):
    case_settings = Lobotomy.get_settings(database)
    profile = case_settings["profile"]
    while profile is '0':
        print 'Waiting for imageinfo...'
        time.sleep(5)
        case_settings = Lobotomy.get_settings(database)
        profile = case_settings["profile"]
    """
    Add a line for every Lobotomy module you want to run when autostart is enabled
    You can use the following template:
        Lobotomy.add_to_queue('python modulename.py {}'.format(database))
    :param database: The database belonging to the memory dump
    :return:
    """
    if profile.startswith("Win"):
        Lobotomy.write_to_main_log(database, "Executing autostart.py for {}".format(database))

        # Dumping files
        Lobotomy.add_to_queue('python {}volatility_procdump.py {}'.format(Lobotomy.plugin_dir, database), 5)#,
                              # 'Volatility Procdump')
        Lobotomy.add_to_queue('python {}lobotomy_dlldump.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Volatility DLLdump')
        Lobotomy.add_to_queue('python {}lobotomy_moddump.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Volatility Moddump')
        Lobotomy.add_to_queue('python {}lobotomy_photorecdump_proc.py {}'.format(Lobotomy.plugin_dir, database), 6)
                              # description='Volatility Photorec')

        # scanning for services
        Lobotomy.add_to_queue('python {}multiparser.py {} pslist'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility PSlist')
        Lobotomy.add_to_queue('python {}lobotomy_pstree.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility PStree')
        Lobotomy.add_to_queue('python {}multiparser.py {} psscan'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility PSScan')
        Lobotomy.add_to_queue('python {}multiparser.py {} psxview'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility PSXview')
        Lobotomy.add_to_queue('python {}lobotomy_svcscan.py {}'.format(Lobotomy.plugin_dir, database), 3)
                              # description='Volatility SVCscan')
        Lobotomy.add_to_queue('python {}lobotomy_sessions.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility sessions')

        Lobotomy.add_to_queue('python {}lobotomy_driverirp.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility driverirp')

        # Scanning files
        # Lobotomy.add_to_queue('python {}vol_yarascan.py {} index.yara'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility yara scan')

        Lobotomy.add_to_queue('python {}yarascan.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # description='Yarascan')

        Lobotomy.add_to_queue('python {}lobotomy_zookeeper.py {}'.format(Lobotomy.plugin_dir, database), 12)
                                # description='Zookeeper pe scanner')

        Lobotomy.add_to_queue('python {}lobotomy_pescanner_proc.py {}'.format(Lobotomy.plugin_dir, database), 25)
                                # description='Malware Cookbook PE Scanner')

        # Networking
        Lobotomy.add_to_queue('python {}lobotomy_ndispktscan.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Find network artifacts


        # Malware scanning
        Lobotomy.add_to_queue('python {}lobotomy_malprocfind.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Find malicious processes

        Lobotomy.add_to_queue('python {}lobotomy_malsysproc.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Find malicious processes

        Lobotomy.add_to_queue('python {}volatility_malfind.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Find malicious processes


        # Other
        Lobotomy.add_to_queue('python {}lobotomy_aeskeyfind.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Find aeskeys with aeskeyfind

        Lobotomy.add_to_queue('python {}lobotomy_coordinates.py {}'.format(Lobotomy.plugin_dir, database), 4)
                                # Find coordinates in a memorydump

        Lobotomy.add_to_queue('python {}lobotomy_joblinks.py {}'.format(Lobotomy.plugin_dir, database), 10)

        Lobotomy.add_to_queue('python {}lobotomy_iehistory.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Only for Volatility 2.5

        Lobotomy.add_to_queue('python {}lobotomy_threads.py {}'.format(Lobotomy.plugin_dir, database), 10)
                                # Only for Volatility 2.5

        Lobotomy.add_to_queue('python {}lobotomy_memmap.py {}'.format(Lobotomy.plugin_dir, database), 5)
                                # description='Memorymap, to map the virutal and the physical offset'

        Lobotomy.add_to_queue('python {}lobotomy_prefetchparser.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Preftechparser')

        Lobotomy.add_to_queue('python {}lobotomy_mimikatz.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Mimikatz')

        Lobotomy.add_to_queue('python {}volatility_windows.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Windows')

        Lobotomy.add_to_queue('python {}volatility_deskscan.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Volatility deskscan')

        Lobotomy.add_to_queue('python {}volatility_wndscan.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Volatility Wndscan')

        Lobotomy.add_to_queue('python {}lobotomy_autoruns.py {}'.format(Lobotomy.plugin_dir, database), 4)
                              # description='Volatility Memory Custom plugin Autoruns')
        Lobotomy.add_to_queue('python {}lobotomy_memtimeliner.py {}'.format(Lobotomy.plugin_dir, database), 4)
                              # description='Volatility Memory Timeliner')
        Lobotomy.add_to_queue('python {}lobotomy_consoles.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Consoles')
        Lobotomy.add_to_queue('python {}lobotomy_cmdline.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Cmdline')
        Lobotomy.add_to_queue('python {}lobotomy_hivelist.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Hivelist')
        Lobotomy.add_to_queue('python {}lobotomy_hivedump.py {}'.format(Lobotomy.plugin_dir, database), 75)
                              # description='Volatility Hivelist')
        Lobotomy.add_to_queue('python {}multiparser.py {} handles'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Handles')
        Lobotomy.add_to_queue('python {}multiparser.py {} clipboard'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Clipboards')
        Lobotomy.add_to_queue('python {}multiparser.py {} ldrmodules'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Ldrmodules')
        Lobotomy.add_to_queue('python {}lobotomy_ldrmodules_v.py {}'.format(Lobotomy.plugin_dir, database), 2)
                              # description='Volatility Ldrmodules -v')
        Lobotomy.add_to_queue('python {}multiparser.py {} atoms'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Atoms')
        Lobotomy.add_to_queue('python {}lobotomy_dlllist.py {}'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility DLLlist')
        Lobotomy.add_to_queue('python {}lobotomy_cmdscan.py {}'.format(Lobotomy.plugin_dir, database), 4)
                              # description='Volatility Cmdscan')
        Lobotomy.add_to_queue('python {}lobotomy_ssdt.py {}'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility SSDT')
        Lobotomy.add_to_queue('python {}lobotomy_getsids.py {}'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Getsids')
        Lobotomy.add_to_queue('python {}multiparser.py {} driverscan'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Driverscan')
        Lobotomy.add_to_queue('python {}multiparser.py {} envars'.format(Lobotomy.plugin_dir, database), 2)
                                      # description='Volatility Envars')
        Lobotomy.add_to_queue('python {}multiparser.py {} filescan'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Filescan')
        Lobotomy.add_to_queue('python {}multiparser.py {} callbacks'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Callbacks')
        Lobotomy.add_to_queue('python {}multiparser.py {} thrdscan'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Thrdscan')
        Lobotomy.add_to_queue('python {}multiparser.py {} atomscan'.format(Lobotomy.plugin_dir, database))
                              # description='Volatility Atomscan')
        # Lobotomy.add_to_queue('python {}multiparser.py {} clipboard'.format(Lobotomy.plugin_dir, database), 10,
        #                       description='Volatility Clipboar')
        Lobotomy.add_to_queue('python {}multiparser.py {} gditimers'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility GDItimers')
        Lobotomy.add_to_queue('python {}multiparser.py {} modscan'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Modscan')
        Lobotomy.add_to_queue('python {}lobotomy_modules.py {}'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Modules')
        Lobotomy.add_to_queue('python {}multiparser.py {} mutantscan'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Mutantscan')
        Lobotomy.add_to_queue('python {}multiparser.py {} objtypescan'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Objtypescan')
        Lobotomy.add_to_queue('python {}multiparser.py {} privs'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Privs')
        Lobotomy.add_to_queue('python {}lobotomy_shimcache.py {}'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Shimcache')
        Lobotomy.add_to_queue('python {}multiparser.py {} symlinkscan'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Symlinkscan')
        Lobotomy.add_to_queue('python {}multiparser.py {} timers'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Timers')
        Lobotomy.add_to_queue('python {}lobotomy_hashdump.py {}'.format(Lobotomy.plugin_dir, database), 4)
                              # description='Volatility Hashdump')
        Lobotomy.add_to_queue('python {}multiparser.py {} unloadedmodules'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility Unloaded modules')
        Lobotomy.add_to_queue('python {}volatility_impscan.py {}'.format(Lobotomy.plugin_dir, database), 20)
                              # description='Volatility Impscan') # Imscan after ldrmodules
#        Lobotomy.add_to_queue('python {}lobotomy_threatreport.py {}'.format(Lobotomy.plugin_dir, database), 99)
                              # description='Lobotomy Report')
        Lobotomy.add_to_queue('python {}lobotomy_msf.py {}'.format(Lobotomy.plugin_dir, database), 11)
                              # description='Lobotomy Metasploit Detect')

        Lobotomy.add_to_queue('python {}lobotomy_hashchecker.py {}'.format(Lobotomy.plugin_dir, database), 25)
                              # description='Lobotomy Metasploit Detect')



        #Lobotomy.add_to_queue('python {}multiparser.py {} userhandles'.format(Lobotomy.plugin_dir, database), 10)
        #Lobotomy.add_to_queue('python {}multiparser.py {} vadwalk'.format(Lobotomy.plugin_dir, database), 10)
        #Lobotomy.add_to_queue('python {}dumpfile.py {}'.format(Lobotomy.plugin_dir, database), 6) # Bulkextractor, doen we nog niets mee
        #Lobotomy.add_to_queue('python {}multiparser.py {} gahti'.format(Lobotomy.plugin_dir, database), 10) # gahti werkt niet met multiparser
        #Lobotomy.add_to_queue('python {}getservicesids.py {}'.format(Lobotomy.plugin_dir, database), 10)

        #Lobotomy.add_to_queue('python {}volatility_memmap.py {}'.format(Lobotomy.plugin_dir, database), 24) # Disabled for now. takes a lot of time to complete
        #Lobotomy.add_to_queue('python {}mftparser.py {}'.format(Lobotomy.plugin_dir, database), 3) # MFTParser is niet af.
        #Lobotomy.add_to_queue('python {}kdbgscan.py {}'.format(Lobotomy.plugin_dir, database), 3) # KDBGscan is niet af!

    #if 'XP' in profile:
    if profile.startswith("WinXP"):
        Lobotomy.add_to_queue('python {}lobotomy_sockets.py {}'.format(Lobotomy.plugin_dir, database),)
                              # description='Volatility Sockets')
        Lobotomy.add_to_queue('python {}lobotomy_sockscan.py {}'.format(Lobotomy.plugin_dir, database),)
                              # description='Volatility Sockscan')
        Lobotomy.add_to_queue('python {}multiparser.py {} gdt'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility GDT')
        Lobotomy.add_to_queue('python {}multiparser.py {} idt'.format(Lobotomy.plugin_dir, database), 10)
                              # description='Volatility IDT')
        pass # connections, connscan,  sockscan
#    if profile == "WinVistax86" or profile == "Win7SP1x86" or profile == "Win7SP1x64" or profile == "Elke andere windows vista+ machine":
#        Lobotomy.add_to_queue('python {}netscan.py {}'.format(database))
    if 'Win7' or 'Vista' or 'Win8' in profile:
        Lobotomy.add_to_queue('python {}volatility_netscan.py {}'.format(Lobotomy.plugin_dir, database), 5)
                              # description='Volatility Netscan')

    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: autostart.py <Database>"
    else:
        autostart(sys.argv[1])

