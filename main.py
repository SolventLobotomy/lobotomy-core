#!/usr/bin/env python
# coding=utf8

""" The main Lobotomy process """
__author__ = 'iScripters, W2k8'
# Local version

# 08-aug
# change plugin tables Getsids, PSlist, psscan, pstree, psxview.
# Add empty routine for parsing TimeZone data as TZ_data


import os
import time
import string
import random
import hashlib
import json
import MySQLdb
import MySQLdb.cursors
import datetime
import commands
from configobj import ConfigObj

"""
Plugin tables
"""

tabledata = {

    'aeskeys': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `type` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `key` varchar(128) COLLATE utf8_bin DEFAULT NULL,\
                  `AesExtendedKey` blob,\
                  `constrains` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',


    'atoms': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `session` varchar(11) NOT NULL,\
                  `windowstation` varchar(18) NOT NULL,\
                  `atom` varchar(10) NOT NULL,\
                  `refcount` int(11) NOT NULL,\
                  `hindex` int(11) NOT NULL,\
                  `pinned` int(11) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'atomscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `atomofs` varchar(32) NOT NULL,\
                  `atom` varchar(10) NOT NULL,\
                  `refs` int(11) NOT NULL,\
                  `pinned` int(11) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'autoruns': '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `autoruntype` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `autorun` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'callbacks': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `type` varchar(36) NOT NULL,\
                  `callback` varchar(32) NOT NULL,\
                  `module` varchar(20) NOT NULL,\
                  `details` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'clipboard': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `session` varchar(10) NOT NULL,\
                  `windowstation` varchar(13) NOT NULL,\
                  `format` varchar(18) NOT NULL,\
                  `handle` varchar(10) NOT NULL,\
                  `object` varchar(10) NOT NULL,\
                  `data` varchar(50) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'cmdline': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` int(22) DEFAULT NULL,\
                  `commandline` varchar(1024) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'cmdscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `commandprocess` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `commandhistory` varchar(18) COLLATE utf8_bin NOT NULL,\
                  `application` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `flags` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `commandcount` int(11) NOT NULL,\
                  `lastadded` int(11) NOT NULL,\
                  `lastdisplayed` int(11) NOT NULL,\
                  `firstcommand` int(11) NOT NULL,\
                  `commandcountmax` int(11) NOT NULL,\
                  `processhandle` varchar(18) COLLATE utf8_bin NOT NULL,\
                  `cmd` text COLLATE utf8_bin NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'consoles': '(`id` int(10) NOT NULL AUTO_INCREMENT,\
                  `consoles` varchar(1024) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'coordinates': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `verified` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `coordinates` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `value` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'deskscan': '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `desktop` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `name` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `next` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `sessionid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `desktopinfo` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `fshooks` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `spwnd` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `windows` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `heap` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `size` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `base` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `limit` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `desktoplist` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `ppid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `proccessname` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'dlldump': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `name` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `modulebase` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `modulename` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `result` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `md5` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `sha256` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `filename` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `fullfilename` text COLLATE utf8_bin,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'dlllist': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `pid` int(8) NOT NULL,\
                  `cmd` text COLLATE utf8_bin NOT NULL,\
                  `servicepack` varchar(20) COLLATE utf8_bin NOT NULL,\
                  `base` varchar(18) COLLATE utf8_bin NOT NULL,\
                  `size` varchar(18) COLLATE utf8_bin NOT NULL,\
                  `loadcount` varchar(18) COLLATE utf8_bin NOT NULL,\
                  `dllpath` text COLLATE utf8_bin NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'driverirp': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `DriverName` varchar(32) NOT NULL,\
                  `DriverStart` varchar(16) NOT NULL,\
                  `DriverSize` varchar(16) NOT NULL,\
                  `DriverStartIo` varchar(16) NOT NULL,\
                  `nr` varchar(10) NOT NULL,\
                  `irpname` varchar(64) NOT NULL,\
                  `offset` varchar(32) NOT NULL,\
                  `name` varchar(32) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'driverscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `ptr` int(11) NOT NULL,\
                  `hnd` int(11) NOT NULL,\
                  `start` varchar(10) NOT NULL,\
                  `size` varchar(10) NOT NULL,\
                  `servicekey` varchar(20) NOT NULL,\
                  `name` varchar(12) NOT NULL,\
                  `drivername` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'envars': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `process` varchar(255) NOT NULL,\
                  `block` varchar(32) NOT NULL,\
                  `variable` varchar(255) NOT NULL,\
                  `value` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'exifinfo': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `filename` varchar(255) NOT NULL,\
                  `exifinfo` blob NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'filescan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `ptr` int(11) NOT NULL,\
                  `hnd` int(11) NOT NULL,\
                  `access` varchar(6) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'gahti': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `session` int(11) NOT NULL,\
                  `type` varchar(20) NOT NULL,\
                  `tag` varchar(8) NOT NULL,\
                  `fndestroy` varchar(10) NOT NULL,\
                  `flags` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'gditimers': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `sess` int(11) NOT NULL,\
                  `handle` varchar(10) NOT NULL,\
                  `object` varchar(10) NOT NULL,\
                  `thread` int(11) NOT NULL,\
                  `process` varchar(20) NOT NULL,\
                  `nid` varchar(10) NOT NULL,\
                  `rate` int(11) NOT NULL,\
                  `countdown` int(11) NOT NULL,\
                  `func` varchar(10) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'gdt': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `cpu` int(11) NOT NULL,\
                  `sel` varchar(10) NOT NULL,\
                  `base` varchar(10) NOT NULL,\
                  `limit` varchar(10) NOT NULL,\
                  `type` varchar(14) NOT NULL,\
                  `dpl` int(11) NOT NULL,\
                  `gr` varchar(4) NOT NULL,\
                  `pr` varchar(4) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'getservicessid': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `serviceid` varchar(255) NOT NULL,\
                  `servicename` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'getsids': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` text COLLATE utf8_bin NOT NULL,\
                  `pid` int(11) NOT NULL,\
                  `sid` text COLLATE utf8_bin NOT NULL,\
                  `user` text COLLATE utf8_bin NOT NULL,\
                  `comment` text COLLATE utf8_bin NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'handles': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `pid` int(6) NOT NULL,\
                  `handle` varchar(10) NOT NULL,\
                  `access` varchar(32) NOT NULL,\
                  `type` varchar(26) NOT NULL,\
                  `details` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'hashdump': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `hash` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `uid` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `rid` int(11) DEFAULT NULL,\
                  `lmhash` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `nthash` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'hivedump': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `hivename` varchar(255) NOT NULL,\
                  `lastwritten` varchar(32) NOT NULL,\
                  `key` text COLLATE utf8_bin,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'hivelist': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `virtual` varchar(32) NOT NULL,\
                  `physical` varchar(32) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'hivescan': '',

    'idt': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `cpu` varchar(11) NOT NULL,\
                  `index` varchar(11) NOT NULL,\
                  `selector` varchar(10) NOT NULL,\
                  `value` varchar(10) NOT NULL,\
                  `module` varchar(20) NOT NULL,\
                  `section` varchar(12) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'imageinfo': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `subject` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `value` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'impscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` int(11) DEFAULT NULL,\
                  `base` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `iat` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `call` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `module` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `function` varchar(128) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'joblinks': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  `pid` int(11) NOT NULL,\
                  `ppid` int(11) NOT NULL,\
                  `sess` int(11) NOT NULL,\
                  `jobsess` varchar(6) NOT NULL,\
                  `wow64` varchar(6) NOT NULL,\
                  `total` varchar(6) NOT NULL,\
                  `active` varchar(6) NOT NULL,\
                  `term` varchar(6) NOT NULL,\
                  `joblink` varchar(8) NOT NULL,\
                  `process` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'iehistory': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `Process` varchar(32) NOT NULL,\
                  `PID` varchar(11) NOT NULL,\
                  `CacheType` varchar(16) NOT NULL,\
                  `Offset` varchar(16) NOT NULL,\
                  `RecordLength` varchar(16) NOT NULL,\
                  `Location` text NOT NULL,\
                  `LastModified` text NOT NULL,\
                  `LastAccessed` text NOT NULL,\
                  `Length` varchar(16) NOT NULL,\
                  `FileOffset` varchar(16) NOT NULL,\
                  `DataOffset` varchar(16) NOT NULL,\
                  `DataSize` varchar(16) NOT NULL,\
                  `File` varchar(16) NOT NULL,\
                  `Data` text NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'kdbgscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `kdbg` text COLLATE utf8_bin,\
                  `offsetv` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `offsetp` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `kdbgowner` text COLLATE utf8_bin,\
                  `kdbgheader` text COLLATE utf8_bin,\
                  `version64` text COLLATE utf8_bin,\
                  `sp` int(11) DEFAULT NULL,\
                  `build` text COLLATE utf8_bin,\
                  `ActiveProcessoffset` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `ActiveProcess` text COLLATE utf8_bin,\
                  `LoadedModuleListoffset` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `LoadedModuleList` text COLLATE utf8_bin,\
                  `KernelBase` text COLLATE utf8_bin,\
                  `major` int(11) DEFAULT NULL,\
                  `minor` int(11) DEFAULT NULL,\
                  `kpcr` text COLLATE utf8_bin,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'ldrmodules': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `process` varchar(255) NOT NULL,\
                  `base` varchar(18) NOT NULL,\
                  `inload` varchar(5) NOT NULL,\
                  `ininit` varchar(5) NOT NULL,\
                  `inmem` varchar(5) NOT NULL,\
                  `mappedpath` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'ldrmodules_v': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `process` varchar(255) NOT NULL,\
                  `base` varchar(18) NOT NULL,\
                  `inload` varchar(5) NOT NULL,\
                  `ininit` varchar(5) NOT NULL,\
                  `inmem` varchar(5) NOT NULL,\
                  `mappedpath` varchar(255) NOT NULL,\
                  `loadpath` varchar(255) DEFAULT NULL,\
                  `loadpathpath` varchar(255) DEFAULT NULL,\
                  `loadpathprocess` varchar(255) DEFAULT NULL,\
                  `initpath` varchar(255) DEFAULT NULL,\
                  `initpathpath` varchar(255) DEFAULT NULL,\
                  `initpathprocess` varchar(255) DEFAULT NULL,\
                  `mempath` varchar(255) DEFAULT NULL,\
                  `mempathpath` varchar(255) DEFAULT NULL,\
                  `mempathprocess` varchar(255) DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'lobotomy_threatreport': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `Report` longblob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'malfind': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` int(12) DEFAULT NULL,\
                  `address` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `vadtag` varchar(12) COLLATE utf8_bin DEFAULT NULL,\
                  `protection` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `flags` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `header` blob,\
                  `body` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'malprocfind': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `processname` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `ppid` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `name` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `path` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `priority` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `cmdline` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `user` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `session` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `time` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `cmd` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `phollow` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `spath` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'malsysproc': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pname` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `name` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `path` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `ppid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `time` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `priority` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `cmdline` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `count` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `CmdLinepath` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `expectedparenttime` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `CreateTime` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'memmap': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  `virtual` varchar(32) NOT NULL,\
                  `physical` varchar(32) NOT NULL,\
                  `size` varchar(32) NOT NULL,\
                  `dumpfileoffset` varchar(32) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'memtimeliner': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `date` varchar(32) NOT NULL,\
                  `size` varchar(32) NOT NULL,\
                  `type` varchar(4) NOT NULL,\
                  `mode` varchar(15) NOT NULL,\
                  `uid` int(11) NOT NULL,\
                  `gid` int(11) NOT NULL,\
                  `meta` varchar(25) NOT NULL,\
                  `filename` text NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'mftparser': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `attribute` varchar(56) COLLATE utf8_bin DEFAULT NULL,\
                  `record` int(32) DEFAULT NULL,\
                  `linkcount` int(11) DEFAULT NULL,\
                  `standardinformation_creation` datetime DEFAULT NULL,\
                  `standardinformation_modified` datetime DEFAULT NULL,\
                  `standardinformation_mft_altered` datetime DEFAULT NULL,\
                  `standardinformation_accessdate` datetime DEFAULT NULL,\
                  `standardinformation_type` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filename_creation` datetime DEFAULT NULL,\
                  `filename_modified` datetime DEFAULT NULL,\
                  `filename_mft_altered` datetime DEFAULT NULL,\
                  `filename_accessdate` datetime DEFAULT NULL,\
                  `filename_name_path` varchar(1024) COLLATE utf8_bin DEFAULT NULL,\
                  `data` blob,\
                  `object_id` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `birth_volumeid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `birth_objectid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `birth_domainid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'messagehooks': '',

    'mimikatz': '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `module` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `user` text COLLATE utf8_bin,\
                  `domain` text COLLATE utf8_bin,\
                  `password` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'moddump': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `modulebase` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `modulename` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `result` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `md5` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `sha256` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `filename` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `fullfilename` text COLLATE utf8_bin,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'modscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  `base` varchar(18) NOT NULL,\
                  `size` varchar(18) NOT NULL,\
                  `file` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'modules': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  `base` varchar(18) NOT NULL,\
                  `size` varchar(18) NOT NULL,\
                  `file` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'msfdetect': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `stringsoffset` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(11) DEFAULT NULL,\
                  `pidoffset` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `vpid` int(11) DEFAULT NULL,\
                  `vpidoffset` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `value` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'mutantscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `ptr` int(11) NOT NULL,\
                  `hnd` int(11) NOT NULL,\
                  `signal` int(11) NOT NULL,\
                  `thread` varchar(18) NOT NULL,\
                  `cid` varchar(32) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'ndispktscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                   `Offset` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                   `Source Mac` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                   `Destination Mac` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                   `port` varchar(11) COLLATE utf8_bin DEFAULT NULL,\
                   `Source IP` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                   `Destination IP` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                   `Source Port` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                   `Destination Port` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                   `Flags` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                   PRIMARY KEY (`id`)\
                 ) ENGINE=InnoDB AUTO_INCREMENT=524 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'netscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `proto` varchar(12) COLLATE utf8_bin DEFAULT NULL,\
                  `localaddress` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `foreignadress` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `state` varchar(20) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` int(8) DEFAULT NULL,\
                  `owner` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `createtime` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'objtypescan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `nobjects` varchar(10) NOT NULL,\
                  `nhandles` varchar(10) NOT NULL,\
                  `key` varchar(255) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  `pooltype` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'pe_scan': '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `fullfilename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `original_filename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_compiletime` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_packer` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filetype` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_language` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pe_dll` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `md5` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `sha` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pehash` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `tag` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `filesize` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `yara_results` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'pe_scanner': '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `filename` varchar(256) DEFAULT NULL,\
                  `pe_blob` longblob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',
    # UnicodeDecodeError: 'utf8' codec can't decode byte 0xda in position 916758: invalid continuation byte

    'photorec': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `fullfilename` varchar(255) DEFAULT NULL,\
                  `filename` varchar(255) DEFAULT NULL,\
                  `md5` varchar(32) DEFAULT NULL,\
                  `sha256` char(64) DEFAULT NULL,\
                  `mtime` varchar(32) DEFAULT NULL,\
                  `atime` varchar(32) DEFAULT NULL,\
                  `ctime` varchar(32) DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'plugins': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `name` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `status` int(11) DEFAULT "0",\
                  `started` datetime DEFAULT NULL,\
                  `stopped` datetime DEFAULT NULL,\
                  `pct` int(3) DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'preferences': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `plugin` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `row_id` int(11) DEFAULT NULL,\
                  `action` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'prefetchparser': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `prefetchfile` varchar(255) NOT NULL,\
                  `executiontime` datetime NOT NULL,\
                  `times` int(11) NOT NULL,\
                  `size` int(11) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'printkey': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `register` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `keyname` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `keylegend` varchar(10) COLLATE utf8_bin DEFAULT NULL,\
                  `lastupdated` datetime DEFAULT NULL,\
                  `subkeys` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `type` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `values` text COLLATE utf8_bin,\
                  `legend` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `model` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'privs': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `process` varchar(255) NOT NULL,\
                  `value` int(11) NOT NULL,\
                  `privilege` varchar(255) NOT NULL,\
                  `attributes` varchar(255) NOT NULL,\
                  `description` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'procdump': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `process` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `imagebase` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `name` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `result` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `md5` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `filename` varchar(255) COLLATE utf8_bin DEFAULT NULL,\
                  `fullfilename` text COLLATE utf8_bin,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'procstrings': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `name` varchar(256) COLLATE utf8_bin NOT NULL,\
                  `virtual` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `physical` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `size` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `dumpfileoffset` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `offsetstrings` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `string` longblob NOT NULL,\
                  `blob` longblob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'pslist': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `name` varchar(20) NOT NULL,\
                  `pid` varchar(11) NOT NULL,\
                  `ppid` varchar(11) NOT NULL,\
                  `thds` varchar(11) NOT NULL,\
                  `hnds` varchar(11) NOT NULL,\
                  `sess` varchar(11) NOT NULL,\
                  `wow64` varchar(11) NOT NULL,\
                  `start` text NOT NULL,\
                  `exit` text NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'psscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `name` varchar(255) NOT NULL,\
                  `pid` varchar(11) NOT NULL,\
                  `ppid` varchar(11) NOT NULL,\
                  `pdb` varchar(18) NOT NULL,\
                  `timecreated` text NOT NULL,\
                  `timeexited` text NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'pstree': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `depth` int(11) DEFAULT NULL,\
                  `offset` varchar(20) DEFAULT NULL,\
                  `name` varchar(50) NOT NULL,\
                  `pid` varchar(11) NOT NULL,\
                  `ppid` varchar(11) NOT NULL,\
                  `thds` varchar(11) NOT NULL,\
                  `hnds` varchar(11) NOT NULL,\
                  `plugin_time` text NOT NULL,\
                  `audit` text,\
                  `cmd` text,\
                  `path` text,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'psxview': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `name` varchar(20) NOT NULL,\
                  `pid` varchar(11) NOT NULL,\
                  `pslist` varchar(6) NOT NULL,\
                  `psscan` varchar(6) NOT NULL,\
                  `thrdproc` varchar(8) NOT NULL,\
                  `pspcid` varchar(6) NOT NULL,\
                  `csrss` varchar(5) NOT NULL,\
                  `session` varchar(7) NOT NULL,\
                  `deskthrd` varchar(8) NOT NULL,\
                  `exittime` text NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'sessions': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `session` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `session_id` int(11) DEFAULT NULL,\
                  `processes` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `PagedPoolStart` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `PagedPoolEnd` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `Process` varchar(32) DEFAULT NULL,\
                  `Processname` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `ProcessTime` text COLLATE utf8_bin,\
                  `Image` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `Adress` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `Name` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'settings': '(`md5hash` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `initialized` datetime NOT NULL,\
                  `filename` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `directory` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `filepath` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `caseid` int(11) NOT NULL,\
                  `profile` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `description` text COLLATE utf8_bin NOT NULL,\
                  `sha256hash` char(64) COLLATE utf8_bin DEFAULT NULL,\
                  `mtime` datetime DEFAULT NULL,\
                  `atime` datetime DEFAULT NULL,\
                  `ctime` datetime DEFAULT NULL,\
                  `image_datetime` datetime DEFAULT NULL,\
                  `image_local_datetime` datetime DEFAULT NULL\
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'shimcache': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `lastmodified` varchar(32) NOT NULL,\
                  `path` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'sockets': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `memtype` varchar(12) DEFAULT NULL,\
                  `offset` varchar(18) NOT NULL,\
                  `pid` int(11) NOT NULL,\
                  `port` int(11) NOT NULL,\
                  `proto` int(11) NOT NULL,\
                  `protocol` varchar(255) NOT NULL,\
                  `address` varchar(255) NOT NULL,\
                  `createtime` datetime NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'sockscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(18) NOT NULL,\
                  `pid` varchar(11) NOT NULL,\
                  `port` int(11) NOT NULL,\
                  `proto` int(11) NOT NULL,\
                  `protocol` varchar(255) NOT NULL,\
                  `address` varchar(255) NOT NULL,\
                  `createtime` varchar(32) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'ssdt': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `ssdt` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `mem1` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `entry` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `mem2` varchar(32) COLLATE utf8_bin NOT NULL,\
                  `systemcall` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `owner` varchar(255) COLLATE utf8_bin NOT NULL,\
                  `hookaddress` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `hookprocess` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'strings': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(22) COLLATE utf8_bin DEFAULT NULL,\
                  `string` text COLLATE utf8_bin,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'svcscan': '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(16) COLLATE utf8_bin DEFAULT NULL,\
                  `order` int(11) DEFAULT NULL,\
                  `start` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `service_name` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `display_name` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `service_type` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `service_state` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `binary_path` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'symlinkscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `ptr` int(11) NOT NULL,\
                  `hnd` int(11) NOT NULL,\
                  `creationtime` text NOT NULL,\
                  `from` varchar(255) NOT NULL,\
                  `to` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'tablehash': '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `plugin` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `hash` varchar(32) DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'thrdscan': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(32) NOT NULL,\
                  `pid` int(11) NOT NULL,\
                  `tid` int(11) NOT NULL,\
                  `startaddress` varchar(18) NOT NULL,\
                  `createtime` text NOT NULL,\
                  `exittime` text NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    # 'threads': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
    #               `ethread` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
    #               `pid` int(12) DEFAULT NULL,\
    #               `tid` int(12) DEFAULT NULL,\
    #               `tags` varchar(128) COLLATE utf8_bin DEFAULT NULL,\
    #               `created` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
    #               `exited` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
    #               `owner` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
    #               `state` varchar(128) COLLATE utf8_bin DEFAULT NULL,\
    #               `blob` blob,\
    #               PRIMARY KEY (`id`)\
    #             ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'threads': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `Offset` varchar(32) DEFAULT NULL,\
                  `PID` int(12) DEFAULT NULL,\
                  `TID` int(12) DEFAULT NULL,\
                  `Tags` varchar(128) DEFAULT NULL,\
                  `Create Time` varchar(32) DEFAULT NULL,\
                  `Exit Time` varchar(32) DEFAULT NULL,\
                  `Owning Process` varchar(32) DEFAULT NULL,\
                  `Attached Process` varchar(128) DEFAULT NULL,\
                  `State` varchar(32) DEFAULT NULL,\
                  `State Reason` varchar(32) DEFAULT NULL,\
                  `Base Priority` varchar(32) DEFAULT NULL,\
                  `Priority` varchar(32) DEFAULT NULL,\
                  `TEB` varchar(32) DEFAULT NULL,\
                  `Start Address` varchar(32) DEFAULT NULL,\
                  `Owner Name` varchar(32) DEFAULT NULL,\
                  `Win32 Start Address` varchar(32) DEFAULT NULL,\
                  `Win32 Thread` varchar(32) DEFAULT NULL,\
                  `Cross Thread Flags` varchar(72) DEFAULT NULL,\
                  `EIP` varchar(32) DEFAULT NULL,\
                  `EAX` varchar(32) DEFAULT NULL,\
                  `EBX` varchar(32) DEFAULT NULL,\
                  `ECX` varchar(32) DEFAULT NULL,\
                  `EDX` varchar(32) DEFAULT NULL,\
                  `ESI` varchar(32) DEFAULT NULL,\
                  `EDI` varchar(32) DEFAULT NULL,\
                  `ESP` varchar(32) DEFAULT NULL,\
                  `EBP` varchar(32) DEFAULT NULL,\
                  `ErrCode` varchar(32) DEFAULT NULL,\
                  `SegCS` varchar(32) DEFAULT NULL,\
                  `SegSS` varchar(32) DEFAULT NULL,\
                  `SegDS` varchar(32) DEFAULT NULL,\
                  `SegES` varchar(32) DEFAULT NULL,\
                  `SegGS` varchar(32) DEFAULT NULL,\
                  `SegFS` varchar(32) DEFAULT NULL,\
                  `EFlags` varchar(32) DEFAULT NULL,\
                  `dr0` varchar(32) DEFAULT NULL,\
                  `dr1` varchar(32) DEFAULT NULL,\
                  `dr2` varchar(32) DEFAULT NULL,\
                  `dr3` varchar(32) DEFAULT NULL,\
                  `dr6` varchar(32) DEFAULT NULL,\
                  `dr7` varchar(32) DEFAULT NULL,\
                  `SSDT` varchar(32) DEFAULT NULL,\
                  `Entry Number` varchar(32) DEFAULT NULL,\
                  `Descriptor Service Table` varchar(32) DEFAULT NULL,\
                  `Hook Number` varchar(32) DEFAULT NULL,\
                  `Function Name` varchar(32) DEFAULT NULL,\
                  `Function Address` varchar(32) DEFAULT NULL,\
                  `Module Name` varchar(32) DEFAULT NULL,\
                  `Disassembly` blob DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'timers': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `offset` varchar(10) NOT NULL,\
                  `duetime` varchar(32) NOT NULL,\
                  `period` int(11) NOT NULL,\
                  `signaled` varchar(3) NOT NULL,\
                  `routine` varchar(10) NOT NULL,\
                  `module` varchar(255) NOT NULL,\
                  PRIMARY KEY (`id`)\
                    ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'unloadedmodules': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `name` varchar(255) NOT NULL,\
                  `startaddress` varchar(32) NOT NULL,\
                  `endaddress` varchar(32) NOT NULL,\
                  `plugin_time` datetime NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'userhandles': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `sharedinfo` varchar(10) NOT NULL,\
                  `sessionid` int(11) NOT NULL,\
                  `shareddelta` int(11) NOT NULL,\
                  `ahelist` varchar(10) NOT NULL,\
                  `tablesize` varchar(10) NOT NULL,\
                  `entrysize` varchar(10) NOT NULL,\
                  `object` varchar(10) NOT NULL,\
                  `handle` varchar(10) NOT NULL,\
                  `btype` varchar(20) NOT NULL,\
                  `flags` int(11) NOT NULL,\
                  `thread` varchar(8) NOT NULL,\
                  `process` varchar(8) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'vadwalk': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `pid` int(11) NOT NULL,\
                  `address` varchar(10) NOT NULL,\
                  `parent` varchar(10) NOT NULL,\
                  `left` varchar(10) NOT NULL,\
                  `right` varchar(10) NOT NULL,\
                  `start` varchar(10) NOT NULL,\
                  `end` varchar(10) NOT NULL,\
                  `tag` varchar(4) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'volatility_yarascan': '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `rule` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `owner` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `owner_name` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` int(11) DEFAULT NULL,\
                  `data_offset` blob,\
                  `data_bytes` blob,\
                  `data_txt` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'warnings': '(`id` int(11) NOT NULL AUTO_INCREMENT,\
                  `plugin` varchar(32) NOT NULL,\
                  `Warning` varchar(1024) NOT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'windows': '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `Windowcontext` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_handle` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_handle_offset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_handle_name` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `classatom` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `window_class` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `superclassatom` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `superwindow_class` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pti` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `tid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `tid_offset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `ppi` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `process` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `visible` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `left` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `top` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `bottom` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `right` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `style_flags` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `exstyle_flags` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `window_procedure` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `data` blob,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'wndscan': '(`id` int(12) NOT NULL AUTO_INCREMENT,\
                  `WindowStation` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `name` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `next` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `sessionid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `atomtable` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `interactive` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `desktops` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `ptiDrawingClipboard` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `spwndClipOpen` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `cNumClipFormats` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `iClipSerialNumber` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `pClipBase` varchar(512) COLLATE utf8_bin DEFAULT NULL,\
                  `Formats` varchar(512) COLLATE utf8_bin DEFAULT NULL,\
                  `spwndClipViewer` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `spwndoffset` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `spwndpid` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  `spwndprocess` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;',

    'wintree': '',

    'yarascan': '(`id` int(11) unsigned zerofill NOT NULL AUTO_INCREMENT,\
                  `filename` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `offset` varchar(32) COLLATE utf8_bin DEFAULT NULL,\
                  `description` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `string` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `yara` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `yara_description` varchar(256) COLLATE utf8_bin DEFAULT NULL,\
                  `pid:offset` varchar(1024) COLLATE utf8_bin DEFAULT NULL,\
                  PRIMARY KEY (`id`)\
                ) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;'
}

# ascii table
#    2 3 4 5 6 7       30 40 50 60 70 80 90 100 110 120
#  -------------      ---------------------------------
# 0:   0 @ P ` p     0:    (  2  <  F  P  Z  d   n   x
# 1: ! 1 A Q a q     1:    )  3  =  G  Q  [  e   o   y
# 2: " 2 B R b r     2:    *  4  >  H  R  \  f   p   z
# 3: # 3 C S c s     3: !  +  5  ?  I  S  ]  g   q   {
# 4: $ 4 D T d t     4: "  ,  6  @  J  T  ^  h   r   |
# 5: % 5 E U e u     5: #  -  7  A  K  U  _  i   s   }
# 6: & 6 F V f v     6: $  .  8  B  L  V  `  j   t   ~
# 7: ´ 7 G W g w     7: %  /  9  C  M  W  a  k   u  DEL
# 8: ( 8 H X h x     8: &  0  :  D  N  X  b  l   v
# 9: ) 9 I Y i y     9: ´  1  ;  E  O  Y  c  m   w
# A: * : J Z j z
# B: + ; K [ k {
# C: , < L \ l |
# D: - = M ] m }
# E: . > N ^ n ~
# F: / ? O _ o DEL
#

replacelist = '0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2e,0x2f,0x3a,0x3b,0x3c,0x3d,' \
              '0x3e,0x3f,0x40,0x5b,0x5c,0x5d,0x5e,0x60,0x7b,0x7c,0x7d,0x7e'


class Lobotomy:
    def __init__(self):

        """
        Get the required info form the ini file.
        If there is no inifile, use the old method.
        """
        filename = os.path.dirname(os.path.abspath(__file__)) + '/lobotomy.ini'
        try:
            self.mysql = []
            with open(filename) as f:
                for line in f:
                    if line.startswith('dumpdir: '):
                        self.dump_dir = line.split(': ')[1].strip('\n')
                    if line.startswith('homedir: '):
                        self.home_dir = line.split(': ')[1].strip('\n')
                    if line.startswith('copydir: '):
                        self.copy_dir = line.split(': ')[1].strip('\n')
                    if line.startswith('plugindir: '):
                        self.plugin_dir = line.split(': ')[1].strip('\n')
                    # if line.startswith('database: '):
                    #     self.db_type(line.split(': ')[1].strip('\n'))
                    if line.startswith('mysqlhost: '):
                        self.mysql.append(line.split(': ')[1].strip('\n'))
                    if line.startswith('mysql_username: '):
                        self.mysql.append(line.split(': ')[1].strip('\n'))
                    if line.startswith('mysql_password: '):
                        self.mysql.append(line.split(': ')[1].strip('\n'))
                    if line.startswith('mysql_template: '):
                        self.mysql.append(line.split(': ')[1].strip('\n'))
                    if line.startswith('yararules: '):
                        self.yararules = line.split(': ')[1].strip('\n')
                    if line.startswith('lobotomy_logfile: '):
                        self.logfile = line.split(': ')[1].strip('\n')
                    if line.startswith('lobotomy_caselogdir: '):
                        self.caselog = line.split(': ')[1].strip('\n')
                    # if line.startswith('lobotomy_triggers: '):
                    #     self.triggerfile = line.split(': ')[1].strip('\n')

                    if line.startswith('bulkinsert: '):
                        self.bulkinsert = line.split(': ')[1].strip('\n')

        except:
            print '\n\nlobotomy.ini not found. using ond method.'
            print 'Please create a file with the name lobotomy.ini in the same folder as main.py'
            print '\nThis is a example of the lobotomy ini file.'
            print 'dumpdir: /dumps/'
            print 'homedir: /srv/lobotomy/'
            print 'copydir: /srv/lobotomy/dumps/'
            print 'plugindir: /srv/lobotomy/lob_scripts/'
            print 'database: mysql'
            print 'mysqlhost: localhost'
            print 'mysql_username: root'
            print 'mysql_password: p@ssw0rd'
            print 'mysql_template: template'
            print 'yararules: /srv/lobotomy/lob_scripts/yara_rules/'
            print 'lobotomy_logfile: /srv/lobotomy/lobotomy.log'
            print 'lobotomy_caselogdir: lobotomy.log\n'

    def write_to_main_log(self, database, message):
        """
        Write a message to the main logfile. The database name will be used as an identifier for the memory dump.
        :param database: The database of the memory dump
        :param message: The message to write to the log
        :return:
        """
        with open(self.logfile, "a") as log:
            now = datetime.datetime.now()
            entry = '{},{},{}\n'.format(now, database, message)
            log.write(entry)

    def write_to_case_log(self, casedir, message):
        """
        Write a message to the logfile in the memory dump's directory.
        :param casedir: The directory belonging to the memory dump
        :param message: The message to write to the log
        :return:
        """
        with open('{}/{}'.format(casedir, self.caselog), "a") as log:
            now = datetime.datetime.now()
            entry = '{},{}\n'.format(now, message)
            log.write(entry)

    def add_to_queue(self, command, priority=3, description=''):
        """
        Add a command to the queue. Commands added to the queue will be executed automatically.
        Note: Enter a command as if you would on the command line, including 'python' if needed and using absolute paths
        :param command: The command to be executed
        :return:
        """
        self.exec_sql_query("INSERT INTO queue (command, priority, added) VALUES ('{}', {}, NOW() {})".format(
            command, priority, description), 'lobotomy')

    def read_from_queue(self):
        """
        Reads, and returns, the first line of the message queue and then removes that line
        :return: The line read
        """
        data = None
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], 'lobotomy',
                              cursorclass=MySQLdb.cursors.DictCursor)
        cur = sql.cursor()
        cur.execute("SELECT id, command, priority FROM queue ORDER BY priority ASC, id ASC LIMIT 1")
        data = cur.fetchone()
        if data is not None:
            cur.execute("INSERT INTO queue_archive SELECT q.*, NOW() FROM queue q WHERE id = {}".format(data['id']))
            sql.commit()
            cur.execute("DELETE FROM queue WHERE id={}".format(data['id']))
            sql.commit()
            return data
        else:
            return None

    def parse_cfg(self, ini):
        """
        Used to parse .ini files accompanying a memory dump.
        :param ini: The filename of the .ini file
        :return: A list with profile, comments, caseid and autostart as presented by the .ini file or 'None' for
                 absent fields
        """
        configfile = self.dump_dir + ini
        config = ConfigObj(configfile)
        try:
            profile = config['profile']
        except KeyError:
            profile = 'None'
        try:
            comments = config['comments']
        except KeyError:
            comments = 'None'
        try:
            autostart = config['autostart']
        except KeyError:
            autostart = 'No'
        try:
            caseid = config['caseid']
        except KeyError:
            caseid = 'None'
        os.remove(self.dump_dir + ini)
        return [profile, comments, caseid, autostart]

    @staticmethod
    def id_generator(size=12, chars=string.ascii_uppercase + string.digits):
        return ''.join(random.choice(chars) for _ in range(size))

    def exec_sql_query(self, query, database):
        """
        Execute an SQL query for use with plugins, this way the individual plugins don't need to import mysqldb
        :param query: The query to be executed
        :param database: The database on which the query should be executed
        :return:
        """
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], database)
        cur = sql.cursor()
        cur.execute(query)
        sql.commit()
        sql.close()

    def md5Checksum(self, filePath):
        # Verify that the path is valid
        if os.path.exists(filePath):

            #Verify that the path is not a symbolic link
            if not os.path.islink(filePath):

                #Verify that the file is real
                if os.path.isfile(filePath):
                    command = 'md5sum {}'.format(filePath)
                    status, log = commands.getstatusoutput(command)
                    return log.split(' ')[0]

                else:
                    print '[{}, Skipped Not a File]'.format(repr(simpleName))
                    return False
            else:
                print '[{}, Skipped Link Not a File]'.format(repr(simpleName))
                return False
        else:
            return False
            pass

    def sha256checksum(self, filepath):
        ONE_MB = 1024000  # 1 MB
        # Verify that the path is valid
        if os.path.exists(filepath):

            #Verify that the path is not a symbolic link
            if not os.path.islink(filepath):

                #Verify that the file is real
                if os.path.isfile(filepath):

                    command = 'sha256sum {}'.format(filepath)
                    status, log = commands.getstatusoutput(command)
                    hexOfHash = log.split(' ')[0]

                    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(filepath)

                    return hexOfHash, mtime, atime, ctime, size

                else:
                    print '[{}, Skipped Not a File]'.format(repr(simpleName))
                    return False
            else:
                print '[{}, Skipped Link Not a File]'.format(repr(simpleName))
                return False
        else:
            return False
            pass

    def create_database(self, dump):
        """
        Creates a database based on the filename of a memory dump and adds all required tables.
        The name will be in the format of "YYMMDDHHMM_filename" without dots.
        For example, a memory dump with the filename 'memorydump1.raw', picked up by the Directory Watcher on
                    05-12-2014 at 12:00 will be named 1412051200_memorydump1raw
        :param dump: The filename of the memory dump
        :return: The name of the newly created database
        """
        prefix = str(time.strftime("%y%m%d%H%M")) + '_'
        databasename = prefix + dump
        databasename = databasename.replace('.', '')
        databasename = databasename.replace(' ', '')
        databasename = databasename.replace('-', '')
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2])
        cur = sql.cursor()
        cur.execute("CREATE DATABASE IF NOT EXISTS {} DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;".format(databasename))
        sql.commit()
        sql.close()
        return databasename

    def populate_database(self, databasename):
        print 'Populating database..'

# Todo
# Create system independent tables.
# After imageinfo is finished, other tables can created based on the profile.

        for table, tablecolumns in tabledata.items():
            if len(tablecolumns) != 0:
                # print '{}\n{}\n{}'.format(databasename, table, tablecolumns)
                # print len(tablecolumns)
                self.createtables(databasename, table, tablecolumns)

        # execute = "mysqldump -u {} -p{} template | mysql -u {} -p{} {}".format(self.mysql[1], self.mysql[2], self.mysql[1], self.mysql[2], databasename)
        # try:
        #     os.system(execute)
        # except:
        #     print "------ ERROR while populating database! ------"
        # finally:
        #     print 'Database populated!'

    def get_settings(self, database):
        """
        Returns a dictionary containing all values from the 'settings' table for the given database
        :param database: The name of the database from which to extract the settings. Returns a dictionary:
        :return: md5hash        varchar(32)
        :return: initialized    DATETIME
        :return: filename       varchar(255)
        :return: directory      varchar(255)
        :return: filepath       varchar(255)
        :return: caseid         INT
        :return: profile        varchar(255)
        :return: description    TEXT
        """
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], database,
                              cursorclass=MySQLdb.cursors.DictCursor)
        cur = sql.cursor()
        cur.execute("SELECT md5hash,initialized,filename,directory,filepath,caseid,profile,description FROM settings")
        settings = cur.fetchone()
        sql.close()
        return settings

    def plugin_start(self, plugin, database):
        # Test if database.table exists
        try:
            self.exec_sql_query("SELECT * FROM {}".format(plugin), database)
        except:
            execute = "mysqldump -u {} -p{} template {} | mysql -u {} -p{} {}".format(self.mysql[1], self.mysql[2], plugin, self.mysql[1], self.mysql[2], database)
            try:
                os.system(execute)
            except:
                print "------ ERROR while populating database! ------"

        # Test if running plugin is in table plugins
        data = None
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], database)
        cur = sql.cursor()
        cur.execute("SELECT name FROM plugins where name='{}'".format(plugin))
        data = cur.fetchone()
        try:
            if plugin not in data:
                pass
        except:
            try:
                # New database layout  with description
                self.exec_sql_query("INSERT INTO plugins VALUES (0, '{}', 0, 0, 0, 0, 0)".format(plugin), database)
            except:
                # old database layout without description
                self.exec_sql_query("INSERT INTO plugins VALUES (0, '{}', 0, 0, 0, 0)".format(plugin), database)

        self.exec_sql_query("UPDATE plugins SET started=NOW(), `status`=2 WHERE `name`='{}'".format(plugin), database)

    def plugin_stop(self, plugin, database):
        self.exec_sql_query("UPDATE plugins SET stopped=NOW(), `status`=1 WHERE `name`='{}'".format(plugin), database)

    def plugin_pct(self, plugin, database, pct):
        self.exec_sql_query("UPDATE plugins SET pct='{}' WHERE `name`='{}'".format(pct, plugin), database)

    def autostart_data(self, database):
        try:
            self.exec_sql_query("SELECT * FROM `autostart`", database)
        except:
            print "------ ERROR reading autostart! ------"

        # Test if running plugin is in table plugins
        data = None
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], database)
        cur = sql.cursor()
        cur.execute("SELECT * FROM `autostart`")
        data = cur.fetchall()
        if data is not None:
            return data
        else:
            return None

    def get_databasedata(self, kolom, plugin, database):
        """
        Reads and returns the data from the requested database table
        :return: The data from the requested table
        """
        try:
            self.exec_sql_query("SELECT " + kolom + " FROM " + plugin, database)
        except:
            return None

        # Test if running plugin is in table plugins
        data = None
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], database)
        cur = sql.cursor()
        cur.execute("SELECT " + kolom + " FROM " + plugin)
        data = cur.fetchall()
        if data is not None:
            return data
        else:
            return None

    def get_databasecolumndata(self, plugin, database):
        """
        Reads and returns the data from the requested database table
        :return: The data from the requested table
        """
        try:
            self.exec_sql_query("SHOW COLUMNS FROM {}".format(plugin), database)
        except:
            return None

        # Test if running plugin is in table plugins
        data = None
        sql = MySQLdb.connect(self.mysql[0], self.mysql[1], self.mysql[2], database)
        cur = sql.cursor()
        # show columns from aeskeys in 1610141233_stuxnetvmem
        # cur.execute("SELECT COLUMNS FROM {} in {}".format(plugin, database))
        cur.execute("SELECT * FROM {} where 1=0".format(plugin))
        # print cur.fetchone
        # print cur.description
        data = cur.description
        # print data
        if data is not None:
            return data
        else:
            return None

    def hash_table(self, tabledata, database):
        """
        Reads and hash the table data from the requested database table
        :return: The Hashvalue from the requested table as MD5 hash
        """
        #test database table
        # /*Table structure for table `tablehash` */
        if self.get_databasedata('*', 'tablehash', database) is None:
            # print 'Sql table not found. Creating table tablehash'
            self.exec_sql_query("CREATE TABLE `tablehash` (\
                      `id` int(12) NOT NULL AUTO_INCREMENT,\
                      `plugin` varchar(64) COLLATE utf8_bin DEFAULT NULL,\
                      `hash` varchar(32) DEFAULT NULL,\
                      PRIMARY KEY (`id`)\
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;", database)

        #tablehash = hashlib.md5(json.dumps(tabledata, sort_keys=True)).hexdigest()
        tablehash = hashlib.md5(json.dumps(tabledata)).hexdigest()

        return tablehash

    def testdatabase(self, database, plugin, tabledata):
        # if self.get_databasedata('*', '{}'.format(plugin), database) is not None:
        #     # print 'Sql table found. Dropping table {}'.format(plugin)
        #     self.exec_sql_query("DROP TABLE IF EXISTS `{}`;".format(plugin), database)

        if self.get_databasedata('*', plugin, database) is None:
            # print 'Sql table {} not found. Creating table {}.'.format(plugin, plugin)
            self.exec_sql_query("CREATE TABLE `{}` {}".format(plugin, tabledata), database)

        # # Truncate current table
        # sql_cmd = "DELETE from {}".format(plugin)
        # try:
        #     self.exec_sql_query(sql_cmd, database)
        # except:
        #     print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        #     print 'SQL Error: {}'.format(sql_cmd)

    def replacechar(self, text):
        global warning
        test = text
        for item in replacelist.split(','):
            text = text.replace(chr(int(item, 16)), '')
        if test != text and warning == 0:
            print 'Illegal char(s) removed'
            warning = 1
        return text

    def createtables(self, database, plugin, columns):
        if self.get_databasedata('*', '{}'.format(plugin), database) is not None:
            # print 'Sql table found. Dropping table {}'.format(plugin)
            self.exec_sql_query("DROP TABLE IF EXISTS `{}`;".format(plugin), database)

        if self.get_databasedata('*', plugin, database) is None:
            # print 'Sql table {} not found. Creating table {}.'.format(plugin, plugin)
            self.exec_sql_query("CREATE TABLE `{}` {}".format(plugin, columns), database)

    def truncatetables(self, database, plugin):
        # Truncate current table
        sql_cmd = "DELETE from {}".format(plugin)
        self.exec_sql_query(sql_cmd, database)

        # Set Autoincrement to 1
        sql_cmd = "ALTER TABLE {} auto_increment=1".format(plugin)
        self.exec_sql_query(sql_cmd, database)
        # except:
        #     print 'SQL Error in {}, plugin: {}'.format(database, plugin)
        #     print 'SQL Error: {}'.format(sql_cmd)

    def pl(self, printline):
        rows, columns = os.popen('stty size', 'r').read().split()
        if len(printline) > int(columns) - 4:
            printline = '{}...{}'.format(printline[0:int(columns) - 12], printline[(len(printline) - 9):len(printline)])
        print printline

    def register_plugin(self, start_stop, database, plugin):

        case_settings = self.get_settings(database)
        imagename = case_settings["filepath"]
        imagetype = case_settings["profile"]
        casedir = case_settings["directory"]
        plugin_dir = self.plugin_dir + 'plugins'

        if start_stop == 'start':
            for table, tablecolumns in tabledata.items():
                if table == plugin:
                    self.testdatabase(database, plugin, tablecolumns)
            self.truncatetables(database, plugin)
            self.write_to_case_log(casedir, 'Database: {} Start plugin: {}'.format(database, plugin))
            self.plugin_start(plugin, database)
            self.plugin_pct(plugin, database, 1)
            return case_settings, imagename, imagetype, casedir, plugin_dir

        if start_stop == 'test':
            for table, tablecolumns in tabledata.items():
                if table == plugin:
                    self.testdatabase(database, plugin, tablecolumns)
            # self.truncatetables(database, plugin)
            self.write_to_case_log(casedir, 'Database: {} Start plugin: {}'.format(database, plugin))
            self.plugin_start(plugin, database)
            self.plugin_pct(plugin, database, 1)
            # return case_settings, imagename, imagetype, casedir, plugin_dir

        if start_stop == 'stop':
            self.write_to_case_log(casedir, 'Database: {} Stop plugin: {}'.format(database, plugin))
            self.plugin_stop(plugin, database)
            self.plugin_pct(plugin, database, 100)

    def plugin_log(self, start_stop, database, plugin, casedir, command):
        self.write_to_main_log(database, "{}: {} plugin: {} cmd: {}".format(start_stop, database, plugin, command))
        self.write_to_case_log(casedir, "{}: {} plugin: {} cmd: {}".format(start_stop, database, plugin, command))

    def hashdata(self, database, plugin, data):
        # Hash the output from volatility
        tablehash = self.hash_table(data, database)
        sql_data = 'INSERT INTO `tablehash` VALUES (0, "{}", "{}")'.format(plugin, tablehash)
        self.exec_sql_query(sql_data, database)

    def escchar(self, line):
        line = line.replace('\\', '\\\\').replace("'", "\"").replace('"', '\"')
        return line

    def save_log(self, imagename, plugin, log):
        f = open('{}-{}.txt'.format(imagename, plugin), 'w')
        f.write(log)
        f.close()

    def tz_data(self, data, plugin, database):
        '''
        :param database: name of the database
        :param plugin: name of the plugin
        :param data: date/time that need to converted. input is the date/time from the image
        :return: returns the converted local date/time
        '''

    def save_query(self, data, plugin, database):
        '''
        :param data: Needs to be a list.
        :param plugin: The name of the running plugin
        :param database: The name of the database
        :return:
        '''

    def read_threatlist_from_file(self):
        lobotomy_threatlist = []
        # Read Local lobotomy_threatlist.txt (case folder) for extra IOC's or custom searches.
        # try:
        #     with open(casedir + '/lobotomy_threatlist.txt') as f:
        #         for line in f:
        #             if not line.startswith('#'):
        #                 lobotomy_threatlist.append(line)
        # except IOError:
        #     pass # No lobotomy_threatlist.txt found in case folder. Continue.
        #
        # Read Global lobotomy_threatlist.txt for extra IOC's or custom searches.
        with open('lobotomy_threatlist.txt') as f:
            for line in f:
                if not line.startswith('#'):
                    lobotomy_threatlist.append(line)
        return lobotomy_threatlist
