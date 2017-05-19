"""
**** Wayne Havey & John Parish
**** Mitre 2016
**** Does the conversion from cuckoo reports in json format to Arff to be digested by weka.
**** Extracts relevant vector features from each json file and places them in a arff file format.
"""

import os
import json
import sys
import magic

# Our list of api categories and which calls fall under them. By no means a comprehensive list. 
features = {'directories_created':['CreateDirectoryW'],
        'directories_deleted':['RemoveDirectoryA','RemoveDirectoryW'],
        'directories_searched':['NtQueryDirectoryFile','FindFirstFileExA','NtOpenDirectoryObject','FindFirstFileExW'],
        'files_copied':['CopyFileW','CopyFileA','CopyFileExW'],
        'files_created':['NtCreateFile'],
        'files_deleted':['DeleteFileW','DeleteFileA'],
        'files_executed':['ShellExecuteExW'],
        'files_modified':['NtSetInformationFile'],
        'files_moved':['MoveFileWithProgressW'],
        'files_opened':['NtOpenFile'],
        'files_read':['NtReadFile','NtQueryInformationFile'],
        'files_written':['NtWriteFile'],
        'mutexes_created':['NtCreateMutant'],
        'mutexes_opened':['NtOpenMutant'],
        'network_connections':['socket','bind','connect','setsockopt','send','WSARecv','closesocket','select','InternetOpenW','gethostbyname','InternetOpenUrlA','InternetReadFile','InternetCloseHandle','URLDownloadToFileW','InternetConnectA','HttpOpenRequestA','HttpSendRequestA','HttpSendRequestW','InterenetWriteFile','WSASend','WSASocketA','listen','accept','WSAStartup','getaddrinfo','GetAddInfoW'],
        'processes_created':['CreateProcessInternalW'],
        'processes_exited':['ExitProcess','NtTerminateProcess'],
        'processes_modified':['LookupPrivilegeValueW','NtDelayExecution','GetSystemMetrics'],
        'procmem_read':['ReadProcessMemory'],
        'procmem_written':['WriteProcessMemory'],
        'regkeys_closed':['RegCloseKey'],
        'regkeys_created':['RegCreateKeyExW','RegCreateKeyExA','NtCreateKey'],
        'regkeys_deleted':['RegDeleteValueA','RegDeleteKeyW','RegDeleteValueW','RegDeleteKeyA'],
        'regkeys_opened':['RegOpenKeyExA','RegOpenKeyExW','NtOpenKey'],
        'regkeys_read':['RegQueryValueExW','NtQueryValueKey','RegQueryValueExA','RegEnumKeyExA','RegEnumKeyExW','RegEnumValueW','RegQueryInfoKeyW','NtQueryKey','RegEnumKeyW','RegEnumValueA','RegQueryInfoKeyA','NtEnumerateValueKey','NtEnumerateKey'],
        'regkeys_written':['RegSetValueExW','RegSetValueExA'],
        'services_created':['CreateServiceA'],
        'services_modified':['ControlService','OpenSCManagerA','OpenSCManagerW'],
        'services_opened':['OpenServiceW','OpenServiceA'],
        'services_started':['StartServiceA','StartServiceW'],
        'threads':['CreateThread','ExitThread','NtGetContextThread','NtSetContextThread','NtResumeThread','CreateRemoteThread','NtOpenThread','NtSuspendThread','NtTerminateThread','RtlCreateUserThread'],
        'dlls_loaded':['LdrLoadDll'],
        'libraries_loaded':['LdrGetDllHandle'],
        'winhooks_used':['SetWindowsHookExA','SetWindowsHookExW','UnhookWindowsHookEx'],
        'debugger_check':['IsDebuggerPresent'],
        'memory_modified':['NtFreeVirtualMemory','NtCreateSection','ZwMapViewOfSection','NtOpenSection','VirtualProtectEx','NtProtectVirtualMemory','NtReadVirtualMemory','NtWriteVirtualMemory'],
        'system_modified':['NtCreateNamedPipeFile','NtMakeTemporaryObject']}

def get_filetypes():

	filetypes_read = open('/home/detbox/cuckoo/det-chamber/files/filetypes.txt')
	filetypes = [i.replace('\n','') for i in filetypes_read]
	filetypes_read.close()
	return filetypes

# Create a test arff file.
def make_header():
	arff = open('arff_test.arff','w')
    
    	print >> arff, '@relation cuckoo_testarff\n'
    
    	for feat in features.iterkeys():
        	print >> arff, '@attribute {} numeric'.format(feat)

    	print >> arff, '@attribute class {', 

    	for types in iter(get_filetypes()):
		print >> arff, types.replace('\n','') + '_good,',
		print >> arff, types.replace('\n','') + '_bad,',

    	print >> arff, '}'
    	print >> arff, '\n@data'

	arff.close()


def expectation(reportData):
    # Determine file type and assume malware status
    ftype = reportData["target"]["file"]["type"]
    fExt = reportData["target"]["file"]["name"]
    if ftype[0:3] == "ELF":
	return "elf_good"
    if "shell script" in ftype:
	return "sh_good"
    try:
	fExtSimple = fExt.split('.')[-1]
	if fExtSimple in ["1","2","3"]:
	    fExtSimple = fExt.split('.')[2]
	if fExtSimple not in iter(get_filetypes()):
	    print '\nUntrained file type: {} submitted'.format(fExtSimple) 
	    print >> open('files/filetypes.txt','a'), fExtSimple
            return 'other' + '_good'
	return fExtSimple + '_good'
    except:
	if 'xml' in ftype.lower():
	    	return 'xml' + '_good'
	elif 'xhtml' in ftype.lower():
	    	return 'xhtml' + '_good'
	else:
	    	return 'other' + '_good'
	

def convert(reportData,name):

    # Initialize all attribute counters to 0 for every report
    features_counts = {'directories_created':0,
    'directories_deleted':0,
    'directories_searched':0,
    'files_copied':0,
    'files_created':0,
    'files_deleted':0,
    'files_executed':0,
    'files_modified':0,
    'files_moved':0,
    'files_opened':0,
    'files_read':0,
    'files_written':0,
    'mutexes_created':0,
    'mutexes_opened':0,
    'network_connections':0,
    'processes_created':0,
    'processes_exited':0,
    'processes_modified':0,
    'procmem_read':0,
    'procmem_written':0,
    'regkeys_closed':0,
    'regkeys_created':0,
    'regkeys_deleted':0,
    'regkeys_opened':0,
    'regkeys_read':0,
    'regkeys_written':0,
    'services_created':0,
    'services_modified':0,
    'services_opened':0,
    'services_started':0,
    'threads':0,
    'dlls_loaded':0,
    'libraries_loaded':0,
    'winhooks_used':0,
    'debugger_check':0,
    'memory_modified':0,
    'system_modified':0}
 
    # Parse API calls by category and increment feature counts
    try:
	# Cuckoo 2.0 made an 'apistats' summary in the JSON that made this process a 
	# whole lot easier. 
	api_sect = reportData["behavior"]["apistats"]
	
	# grabs the count for each api call captured
    	for sub in api_sect:
		for api in api_sect[sub]:
                	api2 = api
                	count = api_sect[sub][api]

            		# Categories misc and anomaly are so seldom that 
            		# we can merge with system category
			for category,api_calls in features.iteritems():
                		if api2 in api_calls:
                    			features_counts[category] += count

    except Exception, e:
	print "\nERROR IN PARSING JSON\n{}\n".format(e)
	pass
        
    # If the arff test file hasnt been made create the header for it
    if not os.path.exists('arff_test.arff'):	
	try:
    		make_header()
	except Exception, e:
		print e

    test_file = open('arff_test.arff','a')

    try:
    	instance_values = '{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},'.format(*features_counts.itervalues()).rstrip()

	# Append to arff file
    	print >> test_file, instance_values,
    	print >> test_file, expectation(reportData),
    	print >> test_file, ' %' + name[-1]

    	return instance_values
    except Exception,e:
    	print "\nError making arff test: {}\n".format(e)
