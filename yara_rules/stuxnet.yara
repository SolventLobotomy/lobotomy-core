rule Stuxnet 
{
    meta:
        description = "Stuxnet"
        author = "w2k8"
        last_modified = "2015-07-06"
    
    strings:
        $string1 = "mrxcls"
        $string2 = "mrxnet"
		$string3 = "HKEY_LOCAL_MACHINE?SYSTEM?CurrentControlSet?Services?MRxCls"
		$file1 = "mdmcpq3.PNF"
		$file2 = "mdmeric3.PNF"
		$file3 = "oem6C.PNF"
		$file4 = "oem7A.PNF"
		$file5 = "mrxnet.sys"
		$file6 = "mrxcls.sys"
        
    condition:
       any of ($string*) or all of ($file*)
}
