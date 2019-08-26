#!/usr/bin/env python
"""
(c) Peter Van Eeckhoutte 2009-2010
U{Peter Van Eeckhoutte - corelan.<http://www.corelan.be:8800>}

peter.ve@corelan.be
corelanc0d3r

$Date: 2011-01-11 12:20:33 +0100 (di, 11 jan 2011) $ 
$Revision: 61 $

"""
__VERSION__ = '2.0.13'
__DBG__ = 'Immunity Debugger v1.73'
import immlib
import getopt
import immutils
from immutils import *
import struct
import binascii, re
from libstackanalyze import *
import urllib
import shutil
import sys
import time
import datetime

DESC = "corelanc0d3r's toolkit for exploit development. Warning : This is just a tool. It requires brains and creativity !"

"""
Global stuff
"""
g_modules=[]
g_mods=[]
g_naslrlist=[]

def usage(imm):
	imm.log("")
	imm.log("")
	imm.log("=" * 145)
	imm.log("     !pvefindaddr - PyCommand for %s - Current plugin version : %s " % (__DBG__,__VERSION__))
	imm.log("     Written by Peter Van Eeckhoutte  (aka corelanc0d3r) - http://www.corelan.be:8800")
	imm.log("     http://redmine.corelan.be:8800 - peter.ve@corelan.be")
	imm.log("    |------------------------------------------------------------------|",highlight=1)
	imm.log("    |                         __               __                      |",highlight=1)
	imm.log("    |   _________  ________  / /___ _____     / /____  ____ _____ ___  |",highlight=1)
	imm.log("    |  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |",highlight=1)
	imm.log("    | / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |",highlight=1)
	imm.log("    | \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |",highlight=1)
	imm.log("    |                                                                  |",highlight=1)
	imm.log("    |------------------------------------------------------------------|",highlight=1)
	imm.log("")
	imm.log("!pvefindaddr Usage")
	imm.log("------------------")
	imm.log("")
	imm.log("   !pvefindaddr <operation> [<options>]")
	imm.log("")
	imm.log("Valid operations:")
	imm.log("")
	imm.log("* update [get]                 (Checks if an updated version of this plugin is available for download)")
	imm.log("                                If you specify the optional get parameter, the plugin will update itself")
	imm.log("* selfupdate                    (Does the same as 'update get')")
	imm.log("* find bytes [-a access] [-l startaddress] [-t endaddress] [-m <module>] [-c]")
	imm.log("                               (Finds all instances of a sequence of bytes in memory")
	imm.log("                                and shows some information about each location")
	imm.log("                                The bytes to search for should be 2 char aligned, no spaces, no 0x or \\x")
	imm.log("                                You can optionally filter on the access level for each location :")
	imm.log("                                r (read), w (write), x (executable)")
	imm.log("                                rw (read and write), rx (read and executable), rwx and wx")
	imm.log("                                Option -m takes precedence over -l and -t")
	imm.log("                                Option -c : skip consecutive pointers")
	imm.log("* a [-m <module>] [-n] [-o]    (look for add esp 8/ret (pop pop ret alternative)) - optionally specify module to filter on")
	imm.log("                                Only addresses from non-safeseh and non-aslr modules will be listed")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("* p [-m <module>] [-r <reg>] [-n] [-o]")
	imm.log("                               (look for pop pop ret) - optionally specify reg and module to filter on")
	imm.log("                                Only addresses from non-safeseh protected modules/binaries will be listed")
	imm.log("                                Unless you have specified a reg and module")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to file ppr.txt")
	imm.log("* p1 [-m <module>] [-r <reg>] [-n] [-o]")
	imm.log("                               (look for pop pop ret) - optionally specify reg and module to filter on")
	imm.log("                                Only addresses from non-safeseh protected and non-aslr/non-fixup modules/binaries will be listed")
	imm.log("                                Unless you have specified a reg and module")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to file ppr1.txt")
	imm.log("* p2 [-m <module>] [-r <reg>] [-n] [-o]")
	imm.log("                               (look for pop pop ret) - optionally specify reg and module to filter on")
	imm.log("                                This will perform a normal search for pop pop ret addresses (also in safeseh compiled modules")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to file ppr2.txt")
	imm.log("* xp [-m <module>] [-r <reg>] [-n] [-o]")
	imm.log("                               (look for xor pop pop ret) - optionally specify reg and module to filter on")
	imm.log("                                Only addresses from non-safeseh protected modules/binaries will be listed")
	imm.log("                                Unless you have specified a reg and module")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to file xppr.txt")
	imm.log("* xp1 [-m <module>] [-r <reg>] [-n] [-o]")
	imm.log("                               (look for xor pop pop ret) - optionally specify reg and module to filter on")
	imm.log("                                Only addresses from non-safeseh protected and non-aslr/non-fixup modules/binaries will be listed")
	imm.log("                                Unless you have specified a reg and module")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to file xppr1.txt")
	imm.log("* xp2 [-m <module>] [-r <reg>] [-n] [-o]")
	imm.log("                               (look for xor pop pop ret) - optionally specify reg and module to filter on")
	imm.log("                                This will perform a normal search for pop pop ret addresses (also in safeseh compiled modules")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to file xppr2.txt")
	imm.log("* jseh [all]                   (look for jmp/call dword ptr[ebp/esp+nn and ebp-nn] + add esp,8+ret)")
	imm.log("                                Only addresses outside address range of modules will be listed")
	imm.log("                                unless parameter 'all' is given. In that case, all addresses will be listed. TRY THIS ONE !")
	imm.log("* j -r <reg> [-m <module>] [-n] [-o]")
	imm.log("                               (look for jmp <reg>, call <reg>, push <reg>+ret) (optionally filter on module)")
	imm.log("                                When option -r reg is not provide, the tool will search for jumps to ESP by default")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Output is written to log and to file j.txt")
	imm.log("* jp -r <reg> [-m <module>]      (look for jmp <reg>, call <reg>, push <reg>+ret) (optionally filter on module),")
	imm.log("                                and then looks for pointers to those addresses")
	imm.log("                                Output is written to log and to file jp.txt. Note : this one can take a long time !")
	imm.log("* jo -r <reg> -l minoffset -t maxoffset [-m <module>] [-n] [-o]")
	imm.log("                                (look for an address that will lead to jump to a register - or + offset )")
	imm.log("                                Output is written to log and to file jo.txt");
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("* fa [byte pattern]            (Find all locations that point to AAAA and then look for locations that point to these pointers)")
	imm.log("                                You can optionally specify your own search pattern (2 or 4 bytes, each byte separated with spaces)")
	imm.log("                                Output is written to log and to file fa.txt")
	imm.log("* fd [allownull]                Find readable memory address which, when multiplied by 2, still points")
	imm.log("                                to a readable address. If parameter 'allownull' is specified, addresses")
	imm.log("                                containing null bytes will be listed as well)")
	imm.log("                                Warning : it might take a few days before this script completes the job !")
	imm.log("* pdep [-r <reg>] [-m <module>] [-n] [-o]")
	imm.log("                               (look for dep bypass instructions such as pop pop pop esp ret)")
	imm.log("                                You can optionally specify reg and module to filter on")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("* depxp                        (List addresses that can be used to set up stack in order to disable DEP - until XP SP3")
	imm.log("* depwin2k3                    (List addresses that can be used to set up stack in order to disable DEP - Win2k3 SP2")
	imm.log("* nosafeseh                    (List all modules that are not safeseh protected)")
	imm.log("* nosafesehaslr                (List all modules that are not safeseh and not aslr protected)")
	imm.log("* noaslr                       (List all modules that are not aslr protected)")
	imm.log("* rop [-m <module>] [-f <filter>] [-n] [-o] [-i] [-r max_ret_value] [-s] [-d] [-c <instruction>]")
	imm.log("                               (List possible ROP gadgets from non-ASLR protected modules. You can optionally filter)")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("                                Option -i : don't show pointers from modules that have the Fixup flag set")
	imm.log("                                Parameter -r allows you to specify the maximum RET offset to look for. Default value : 32")
	imm.log("                                Warning : if you don't specify a module and/or a lower RET offset, the process can take a very long time to complete")
	imm.log("                                The -s option will split the rop output into a dedicated file per module. The filenames will include")
	imm.log("                                modulename, version, OS type and OS version")
	imm.log("                                Option -d will search deeper (longer) and might find possibly interesting gadgets")
	imm.log("                                Option -c + instruction (no quotes, spaces are allowed) will allow you to look for gadgets ending with this instruction")
	imm.log("                                as opposed	to looking for gadgets ending with RET")
	imm.log("* jrop [-m <module>] [-n] [-o] (List possible jumpboards to your ROP chain at ESP, from non-ASLR protected modules. You can optionally filter)")
	imm.log("                                on a specific module. Output will be written to jrop.txt")
	imm.log("                                Obviously, you can just use a RET or directly jump to a ROP gadget as well")
	imm.log("                                Option -n : don't show pointers that contain null bytes")
	imm.log("                                Option -o : don't show pointers from modules in the Windows folder")
	imm.log("* ropcall [-m <module>] [-n]   (Find all 'call' to DEP bypass functions in loaded non-ASLR modules)")
	imm.log("                                Option -m <modulename> will allow you to filter on modulename")
	imm.log("                                Option -n will ignore all pointers that have null bytes")
	imm.log("                                Output will be written to ropcall.txt")
	imm.log("* findmsp [pat]                (Find metasploit pattern offset in registers and/or sehchain records")
	imm.log("                                if [pat] is specified (4 ascii characters or 10 byte address (0xDEADBEEF)), then only offset search is performed")
	imm.log("* pattern_create size          (Create Metasploit pattern of <size> characters)")
	imm.log("                                pattern is displayed in log window and written to file mspattern.txt")
	imm.log("* pattern_offset bytes [size]  (Find bytes (4 ascii characters or 10 byte address (0xDEADBEEF) in Metasploit pattern with length <size>)")
	imm.log("                                If no size is given, a default pattern of 8000 characters is used")
	imm.log("* suggest                      (Suggest a payload based on metasploit offset and whether this is direct RET or SEH overwrite)")
	imm.log("                                Note : this is just a suggestion and may not work - you need to look at registers yourself")
	imm.log("                                if you want to be sure. Also, it will not suggest anything useful when HW DEP/NX is enabled")
	imm.log("* compare file [address]       (Compares memory contents with bytes in a given file. If no address is given, ")
	imm.log("                                the script will try to locate the bytes in memory by looking at the first 8 bytes")
	imm.log("                                All output will be written to file compare.txt")
	imm.log("* assemble <instructions>      (Convert instructions to opcode. Separate multiple instructions with #")
	imm.log("                                You can automatically invoke the encoder on the produced opcodes by adding the ")
	imm.log("                                encode ascii  (or encode alphanum) statement after the instructions")
	imm.log("* offset addr1 addr2           (Calculates number of bytes between two addresses (use this if you are too lazy to use calc)")
	imm.log("                                Note : you can also replace one (or both) addresses with a register")
	imm.log("                                Finally, you can also specify 8 bytes as addr2. The tool will then search for these 8 bytes")
	imm.log("                                and calculate the offset between addr1 and the memory location of these 8 bytes")
	imm.log("                                Format to specify these 8 bytes : use 16 characters, no spaces, and don't start with 0x")
	imm.log("* encode type bytes            (Custom encoder)");
	imm.log("                                Valid type(s) are : ascii and alphanum")
	imm.log("                                Format to specify the bytes : just type the bytes (2 byte aligned) right after each other")
	imm.log("                                Example : !pvefindaddr encode ascii 81C253040000FFE2")
	imm.log("                                Alternatively, you can also specify the filename that contains the bytes to be encoded")
	imm.log("                                Example : !pvefindaddr encode c:\\tmp\\original.bin")
	imm.log("                                You can also specify the address in memory that contains the bytes to be encoded")
	imm.log("                                (start	with -b) followed by the number of bytes, optionally followed by bad chars")
	imm.log("                                Example : !pvefindaddr encode -b0012FC01 78")
	imm.log("                                Finally, you can put a list of badchars (same format as bytes) after the bytecode, filename")
	imm.log("                                or size (if memory address is used)")
	imm.log("                                All output will be written to file encoded.txt")
	imm.log(" * info address                (Will show some information about a given address within the context of the loaded application)")
	imm.log(" * modules                     (Will show table with all loaded modules + some additional info (safeseh, aslr, etc))")
	imm.log(" * functions [ALL]             (Will output pointers to all functions in the application.) If you specify ALL (optional parameter)")
	imm.log("                                then functions from loaded os dll's will be shown as well. Output is written to functions.txt")
	imm.log(" * omelet -f shellcodefile [-s size] [-t tag]")
	imm.log("                               (Will create eggs-to-omelet hunter and egg blocks based on raw shellcode written to file shellcodefile")
	imm.log("                                You can optionally set the size per block (max 123 bytes, default value) and change the tag,")
	imm.log("                                which is set to 303077 by default. If you want to specify your own, make sure it's 6 chars")
	imm.log(" * filecompare -f \"file1,file2,...filen\"")
	imm.log("                               (Will compare the output of files created with pvefindaddr and display the pointers that have been found")
	imm.log("                                in all of the files.) Make sure to use files that are created with the same version of pvefindaddr")
	imm.log("                                and contain the output of the same pvefindaddr command")
	imm.log("                                Put all filenames between one set of double quotes, and separate files with comma's !")
	imm.log("                                Output will be written to filecompare.txt")
	imm.log(" * retslide [-r <value>]       (Will search for ret slides - pointers that consist of 4 times the same bytes (or 2 time 2) and point to RET)")
	imm.log("                                option -r can be used to override the default value of 32 as maximum offset for RET instruction to search for")
	imm.log(" * dump -f <filename> -s <startaddress> -e <endaddress> | -l <nr of bytes>")
	imm.log("                               (Will dump <nr_of_bytes> (decimal integer) from a given memory address (at <startaddress>) to file <filename>")
	imm.log("                                Alternatively you can specify an endaddress (-e) instead of specifying the nr of bytes")	
	imm.log("                                Example : !pvefindaddr dump c:\\temp\\process.bin 0012FA83 120")
	imm.log("")
	imm.log("=" * 145)
	imm.log("")
	imm.log("")


"""
Function to check if updated version of pvefindaddr is available
"""
def findupdate(imm):
	versionurl="http://redmine.corelan.be:8800/projects/pvefindaddr/repository/raw/release/version.txt"
	filename="pvefindaddrlatest.txt"
	imm.log(" ----------------------------------------------------------------------------------------")
	imm.log(" Current version : %s " % __VERSION__)
	newversion=__VERSION__
	try:
		imm.log(" Downloading version information, please wait...")
		imm.updateLog()
		u = urllib.urlretrieve(versionurl)
		imm.log("   -> Download complete - now comparing version information")
		imm.updateLog()
		shutil.move(u[0],filename)
		try:
			fd = open(filename,"rb")
			content = fd.readlines()
			fd.close()
			for eachLine in content:
				newversion=eachLine
				newversion=newversion.replace('\n','')
				if (newversion != __VERSION__):
					imm.log(" [!] Latest published (stable) version of this PyCommand is : v%s" % newversion,highlight=1)
					if (__VERSION__.find("dev") > -1):
						imm.log("     ** You are running a svn/development version of pvefindaddr ** ")
						imm.log("        Use  'svn co http://svn.corelan.be:8800/svn/pvefindaddr' ")
						imm.log("        (or use a GUI client such as TortoiseSVN)")
						imm.log("        to update this version")
					else:
						imm.log("     Go to http://redmine.corelan.be:8800/projects/pvefindaddr")
						imm.log("     to download the latest version of this script")
						imm.log(" [!] You can also run '!pvefindaddr update get'  to download the updated version ")
				else:
					imm.log("   -> You are running the latest version !")
		except:
			imm.log(" *** Unable to verify latest version ***")
	except:
		imm.log(" *** Unable to download version information, try again later ***")
	imm.log(" ----------------------------------------------------------------------------------------")


def getupdate(imm,type):
	versionurl = "http://redmine.corelan.be:8800/projects/pvefindaddr/repository/raw/release/version.txt"
	filename = "pvefindaddrlatest.txt"
	fversion = "v1.73"
	if __DBG__.find("1.8") > -1:
		fversion = "v1.8" 
	appurl="http://redmine.corelan.be:8800/projects/pvefindaddr/repository/raw/" + type + "/" + fversion + "/pvefindaddr.py"
	appfilename="pvefindaddr.tmp"
	imm.log(" ----------------------------------------------------------------------------------------")
	imm.log(" Current version : %s (%s) " % (__VERSION__,type))
	newversion=__VERSION__
	try:
		imm.log(" Downloading version information, please wait...")
		imm.updateLog()
		u = urllib.urlretrieve(versionurl)
		imm.log("   -> Download complete - now comparing version information")
		imm.updateLog()
		shutil.move(u[0],filename)
		try:
			fd = open(filename,"rb")
			content = fd.readlines()
			fd.close()
			for eachLine in content:
				 newversion=eachLine
			newversion=newversion.replace('\n','')
			if (newversion != __VERSION__) and (__VERSION__.find("dev") == -1):
				imm.log("   -> Downloading version %s" % newversion)
				imm.updateLog()
				try:
					u = urllib.urlretrieve(appurl)
					shutil.move(u[0],appfilename)
					fd = open(appfilename,"rb")
					content = fd.readlines()
					fd.close()
					linecnt=0
					for eachLine in content:
						 linecnt=linecnt+1
					imm.log("   -> Download complete, read %d lines" % linecnt)
					if linecnt > 1000:
						imm.log("   -> Putting updated file in place")
						apptargetfile=".\\PyCommands\\pvefindaddr.py"
						FILE=open(apptargetfile,"w")
						for eachLine in content:
							FILE.write(eachLine)
						FILE.close()
						imm.log("   -> Update complete")
					else:
						imm.log("   ** Downloaded file is smaller than expected - skipping update for now",highlight=1)
				except:
					imm.log(" *** Unable to update to version %s" % newversion)
			else:
				if (__VERSION__.find("dev")==-1):
					imm.log("   -> You are running the latest version !")
				else:
					imm.log("   -> Downloading svn (development version)")
					imm.updateLog()
					try:
					  u = urllib.urlretrieve(appurl)
					  shutil.move(u[0],appfilename)
					  fd = open(appfilename,"rb")
					  content = fd.readlines()
					  fd.close()
					  linecnt=0
					  for eachLine in content:
						 linecnt=linecnt+1
					  imm.log("   -> Download complete, read %d lines" % linecnt)
					  if linecnt > 1000:
						imm.log("   -> Putting updated file in place")
						apptargetfile=".\\PyCommands\\pvefindaddr.py"
						FILE=open(apptargetfile,"w")
						for eachLine in content:
							FILE.write(eachLine)
						FILE.close()
						imm.log("   -> Update complete")
					  else:
						imm.log("   ** Downloaded file is smaller than expected - skipping update for now ** ",highlight=1)						
					except:
					   imm.log(" *** Unable to update development version")
		except:
			imm.log(" *** Unable to verify latest version ***")
	except:
		imm.log(" *** Unable to download version information, try again later ***")
	imm.log(" ----------------------------------------------------------------------------------------")

	
"""
Function to dump stuff from memory to file
"""
		
def dodump(args):
	imm = immlib.Debugger()
	cnt=1
	filename=""
	startaddress=""
	endaddress=""
	startloc=0
	endloc=0
	nrofbytes=0
	while cnt < len(args):
		if args[cnt]=='-f':
			if cnt < (len(args)-1):
				filename=args[cnt+1]
		if args[cnt]=='-s':
			if cnt < (len(args)-1):
				startaddress=args[cnt+1]
		if args[cnt]=='-l':
			if cnt < (len(args)-1):
				nrofbytes=int(args[cnt+1])
		if args[cnt]=='-e':
			if cnt < (len(args)-1):
				endaddress = args[cnt+1]
		cnt=cnt+1
	if (filename=="" or startaddress=="" or (nrofbytes==0 and endaddress=="")):
		imm.log("Invalid arguments")
		return "Invalid arguments"
	imm.updateLog()
	startaddress=startaddress.replace('0x','')
	startaddress=startaddress.replace('0X','')
	startloc=addresstoint(startaddress)
	endaddress=endaddress.replace('0x','')
	endaddress=endaddress.replace('0X','')
	if endaddress != "":
		endloc=addresstoint(endaddress)
	if endloc == 0:
		endloc = startloc + nrofbytes
		endaddress = tohex(endloc)
	else:
		nrofbytes = endloc - startloc
	imm.log("Reading %d bytes (from %s to %s)..." % (nrofbytes,startaddress,endaddress))		
	bytes=""
	cnt=0
	while cnt<nrofbytes:
		try:
			memchar = imm.readMemory(startloc+cnt,1)
			bytes=bytes+memchar
			cnt=cnt+1
		except:
			cnt=cnt+1
			pass
	imm.log("Writing bytes to file %s" % (filename))
	try:
		FILE=open(filename,"wb")
		FILE.write(bytes)
		FILE.close()
		imm.log("Done")
	except:
		imm.log("Unable to write bytes to file")
	return "Done"



"""
Function to guess start of a long string (AAAA or something like that)
"""
def guessstart(asciivalue,type):
	imm = immlib.Debugger()
	#did we overwrite EIP or seh chain ?
	if type==1:
		#EIP overwritten
		regs = imm.getRegs()
		for reg in regs:
			if reg.upper() == "EIP":
				#in most cases, ESP now points at location right after direct RET was overwritten
				startloc=regs["ESP"]
				imm.log("   Trying to guess the startlocation of the buffer with %s's " % asciivalue)
				imm.log("   Please wait, this may take a long time...")
				imm.updateLog()
				counter=8
				found=0
				matchnull=0
				try:
					while found == 0:
						memchar = imm.readMemory(startloc-counter,4)
						#only react if 2 out of 4 bytes don't match and ignore (but count) null bytes
						match=0
						bytecnt=0
						for mybyte in memchar:
							if (mybyte == asciivalue[bytecnt] or hex(ord(mybyte))=="0x0"):
								match=match+1
								if hex(ord(mybyte)) == "0x0":
									matchnull=matchnull+1
							bytecnt=bytecnt+1
						if (match < 3):
							found=1
							imm.log("   Start of string may have be found at %s " % tohex(startloc-counter+match),address=startloc-counter+match,highlight=1)
							curloc=startloc-counter
							offs=startloc-curloc-8-match
							imm.log("   That means that EIP may have been overwritten after about %d bytes (more or less - I could be wrong !)" % offs)
							imm.log("   (including %d null bytes)" % matchnull)
							imm.log("   Again, this is just a guess - try using a Metasploit pattern instead of %s" % asciivalue)
						counter=counter+4
				except:
					imm.log("   Quit searching (access violation at %s)" % tohex(startloc))
	if type==2:
		imm.updateLog()
		thissehchain=imm.getSehChain()
		nrofentries=0
		for chainentry in thissehchain:
			imm.updateLog()
			sehvalue=tohex(chainentry[1])
			hex1=sehvalue[6]+sehvalue[7]
			hex2=sehvalue[4]+sehvalue[5]
			hex3=sehvalue[2]+sehvalue[3]
			hex4=sehvalue[0]+sehvalue[1]
			sehasciivalue=toascii(imm,hex1)+toascii(imm,hex2)+toascii(imm,hex3)+toascii(imm,hex4)
			if (sehasciivalue == asciivalue):
				startloc=chainentry[0]
				imm.log("   Trying to guess the startlocation of the buffer with %s's " % asciivalue)
				imm.log("   Please wait, this may take a long time...")
				imm.updateLog()
				counter=8
				found=0
				matchnull=0
				try:
					while found == 0:
						memchar = imm.readMemory(startloc-counter,4)
						#only react if 2 out of 4 bytes don't match and ignore (but count) null bytes
						match=0
						bytecnt=0
						for mybyte in memchar:
							 if (mybyte == asciivalue[bytecnt] or hex(ord(mybyte))=="0x0"):
								match=match+1
								if hex(ord(mybyte)) == "0x0":
										matchnull=matchnull+1
							 bytecnt=bytecnt+1
						if (match < 3):
							found=1
							imm.log("   Start of string may have be found at %s " % tohex(startloc-counter+match+8),address=startloc-counter+match+8,highlight=1)
							curloc=startloc-counter+8
							offs=startloc-curloc-match
							imm.log("   That means that SEH may have been overwritten after about %d bytes (more or less - I could be wrong !)" % offs)
							imm.log("   (including %d null bytes... )" % matchnull)
							imm.log("   Again, this is just a guess - try using a Metasploit pattern instead of %s" % asciivalue)
						counter=counter+4
				except:
					imm.log("   Quit searching (access violation at %s)" % tohex(startloc))

"""
Function to build table with all modules and safeseh / aslr / ... info
"""
def moduleinfo():
	imm = immlib.Debugger()
	imm.log("** [+] Gathering executable / loaded module info, please wait...")
	global g_modules
	g_modules=[]
	allmodules=imm.getAllModules()
	global g_mods
	g_mods=allmodules
	global g_nsafelist
	g_nsafelist=[]
	for key in allmodules.keys():
		issafeseh=1
		isaslr=1
		isnx=1
		rebased=0
		mod=imm.getModule(key)
		mzbase=mod.getBaseAddress()
		mzrebase=mod.getFixupbase()
		mzsize=mod.getSize()
		mversion=mod.getVersion()
		mversion=mversion.replace(", ",".")
		mversionfields=mversion.split('(')
		mversion=mversionfields[0].replace(" ","")
		if mversion=="":
			mversion="-1.0-"
		path=mod.getPath()
		osmod=mod.getIssystemdll()
		if osmod==0:
			if path.upper().find("WINDOWS") > -1:
				osmod=1
		mztop=mzbase+mzsize
		if mzbase > 0:
			peoffset=struct.unpack('<L',imm.readMemory(mzbase+0x3c,4))[0]
			pebase=mzbase+peoffset
			flags=struct.unpack('<H',imm.readMemory(pebase+0x5e,2))[0]
			numberofentries=struct.unpack('<L',imm.readMemory(pebase+0x74,4))[0]
			#safeseh ?
			if (flags&0x400)!=0:
				issafeseh=1
			else:
				if numberofentries>10:
					sectionaddress,sectionsize=struct.unpack('<LL',imm.readMemory(pebase+0x78+8*10,8))
					sectionaddress+=mzbase
					data=struct.unpack('<L',imm.readMemory(sectionaddress,4))[0]
					condition=(sectionsize!=0) and ((sectionsize==0x40) or (sectionsize==data))
					if condition==False:
						issafeseh=0
						g_nsafelist.append(key)
					else:
						sehlistaddress,sehlistsize=struct.unpack('<LL',imm.readMemory(sectionaddress+0x40,8))
						if sehlistaddress!=0 and sehlistsize!=0:
							issafeseh=1
			#aslr
			if (flags&0x0040)==0:  # 'IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
				isaslr=0
			if (flags&0x0100)==0:
				isnx=0
			if mzrebase <> mzbase:
				rebased=1
			#       0         1             2               3                4                5                   6               7              8                 9                10
			curmod=key+'\t'+path+'\t'+str(mzbase)+'\t'+str(mzsize)+'\t'+str(mztop)+'\t'+str(issafeseh)+'\t'+str(isaslr)+'\t'+str(isnx)+'\t'+str(rebased)+'\t'+str(mversion)+'\t'+str(osmod)
			g_modules.append(curmod)
		imm.updateLog()
	imm.log("** [+] Finished task, %d modules found" % len(g_modules))
	imm.updateLog()


def getropfilename(modname):
	imm = immlib.Debugger()
	if len(g_modules)==0:
		moduleinfo()
	mfound=0
	strfilename=""
	if modname <> "":
		for mname in g_modules:
				mnamentry=mname.split('\t')
				if mnamentry[0].lower().startswith(modname.lower()):
					mfound=1
					modname=mnamentry[0]
					mversion=mnamentry[9]
					if mversion <> "":
						mversion="_v"+mversion
	if mfound==1:
		osver=imm.getOsVersion()
		osrel=imm.getOsRelease()
		strfilename="rop_" + modname.lower()+mversion+"_"+osver+"_"+osrel+".txt"
	return strfilename



def isosmodule(modname):
	if len(g_modules)==0:
		moduleinfo()
	osmodule=0
	mpath=""
	msystem=""
	mfound=0
	if modname <> "":
		for mname in g_modules:
			mnamentry=mname.split('\t')
			if mnamentry[0].lower().startswith(modname.lower()):
				mfound=1
				mpath=mnamentry[1]
				msystem=mnamentry[10]
	if mfound==1:
		if int(msystem) == 1:
			osmodule=1
		else:
			if mpath.upper().find("WINDOWS") > -1:
				osmodule=1
	return osmodule

def getmodnamefromptr(thisptr):
	if len(g_modules)==0:
		moduleinfo()
	modname=""
	for thismname in g_modules:
		mnamentry=thismname.split('\t')
		thisbase=int(mnamentry[2])
		thistop=int(mnamentry[4])
		if (thisptr >= thisbase) and (thisptr <= thistop):
			modname=mnamentry[0]
	return modname
	
def getmodnamefromname(searchname):
	if len(g_modules)==0:
		moduleinfo()
	modname=""
	searchname = searchname.strip().lower()
	foundname = ""
	for thismname in g_modules:
		mnamentry=thismname.split('\t')
		modname=mnamentry[0].strip().lower()
		if searchname == modname:
			foundname = mnamentry[0]
		else:
			l = len(searchname)
			if l <= len(modname):
				if modname[0:l] == searchname:
					foundname = mnamentry[0]
	return foundname

def getRet(imm, allocaddr, max_opcodes = 500):
	addr = allocaddr
	for a in range(0, max_opcodes):
		op = imm.DisasmForward( addr )
		if op.isRet():
			return op.getAddress()
		addr = op.getAddress()
	return 0x0

def getmoduleprop(modname,parameter):
	imm = immlib.Debugger()
	modname=modname.strip()
	parameter=parameter.lower()
	modname=modname.lower()
	valtoreturn=""
	if parameter=="path":
		field=1
	if parameter=="base":
		field=2
	if parameter=="size":
		field=3
	if parameter=="top":
		field=4
	if parameter=="safeseh":
		field=5
	if parameter=="aslr":
		field=6
	if parameter=="nx":
		field=7
	if parameter=="fixup":
		field=8
	if parameter=="version":
		field=9
	if parameter=="systemdll":
		field=10
	if len(g_modules)==0:
		moduleinfo()
	for mod in g_modules:
		modrecord=mod.split('\t')
		try:
			if modname==modrecord[0].lower().strip():
				 valtoreturn=modrecord[field]
		except:
			valtoreturn=""
	return valtoreturn

 
"""
Function to list all modules that are not safeseh protected
"""

def getnosafeseh(imm):
	nosafesehmod=[]
	if len(g_modules)==0:
		moduleinfo()
	for mods in g_modules:
		modrecord=mods.split('\t')
		if modrecord[5]=="0":
				nosafesehmod.append(modrecord[0])
	return nosafesehmod

"""
Function to get the address of a function from a given module
"""
def getfuncaddress(module,function):
	function=function.lower()
	module=module.lower()
	imm = immlib.Debugger()
	if len(g_modules)==0:
		moduleinfo()
	baseloc=0
	ret=0
	modfound=0
	for mods in g_modules:
		modrecord=mods.split('\t')
		if modrecord[0].lower()==module:
			baseloc=modrecord[2]
			modfound=1
	if modfound==0:
		#load module
		try:
			imm.log(" ** Attempting to load module %s" % (module),highlight=1)
			imm.inject_dll("c:\\windows\\system32\\"+module)
		except:
			pass
		moduleinfo()
		baseloc=0
		modfound=0
		for mods in g_modules:
			modrecord=mods.split('\t')
			if modrecord[0].lower()==module:
				baseloc=int(modrecord[2])
				modfound=1
	if baseloc > 0:
		#load module
		mod=imm.getModule(module)
		mzbase=mod.getBaseAddress()
		if imm.isAnalysed(mzbase) <> 1:
			imm.analyseCode( mzbase )
		imm.updateLog()
		allfuncs=[]
		allfuncs=imm.getAllFunctions(mzbase)
		for thisfunc in allfuncs:
			#Get function name at this address
			funcloc = imm.getFunction( thisfunc )
			ffullname = imm.decodeAddress( thisfunc )
			fname=ffullname.split('.')
			if len(fname) > 0:
				if fname[1].lower()==function:
					ret=thisfunc
	return ret

"""
Function to list all modules that are not aslr aware and not compiled with safeseh either
"""
def getnosafesehaslr(imm,mode):
	nrfound=0
	if len(g_modules)==0:
		moduleinfo()
	for mods in g_modules:
		modrecord=mods.split('\t')
		mzbase=int(modrecord[2])
		mztop=int(modrecord[4])
		path=modrecord[1]
		key=modrecord[0]
		extra=""
		if (modrecord[8]=="1"):
				extra=" - !BaseFixup!"
		else:
				extra=""
		if modrecord[6]=="0":	  #
				if modrecord[5]=="0":
					imm.log("*[+] 0x%08x - 0x%08x : %s %s (*** No ASLR, No Safeseh ***) - %s" % (mzbase,mztop,key,extra,path),highlight=1)
					nrfound=nrfound+1
				else:
					if (mode == 0):
						imm.log(" [-] 0x%08x - 0x%08x : %s %s (No ASLR, but Safeseh protected) - %s" % (mzbase,mztop,key,extra,path))
	imm.log("Number of non-protected modules found : %d" % nrfound)
	imm.log("")



"""
Function to see if a given module is safeseh protected or not
"""
def ismodulenosafeseh(modulename):
	found=0
	modulename=modulename.lower().strip()
	if len(g_modules)==0:
		moduleinfo()
	for mods in g_modules:
		modrecord=mods.split('\t')
		if ((modrecord[0].lower().strip()==modulename) and (modrecord[5]=="0")):
				found=1
	return found

"""
Function to see if a given module is aslr protected or not
"""
def ismodulenoaslr(modulename):
	found=0
	modulename=modulename.lower().strip()
	if len(g_modules)==0:
		moduleinfo()
	for mods in g_modules:
		modrecord=mods.split('\t')
		if ((modrecord[0].lower().strip()==modulename) and (modrecord[6]=="0")):
			found=1
	return found

def shownosafeseh():
	imm = immlib.Debugger()
	cnt=0
	if len(g_modules)==0:
		moduleinfo()
	imm.log("Safeseh unprotected modules : ")
	for mods in g_modules:
		modrecord=mods.split('\t')
		if (modrecord[5]=="0"):
			found=1
			mzbase=int(modrecord[2])
			mztop=int(modrecord[4])
			path=modrecord[1]
			np=modrecord[0]
			imm.log(" * 0x%08x - 0x%08x : %s (%s)" % (mzbase,mztop,np,path),highlight=1)
			imm.updateLog()
			cnt=cnt+1
	if cnt>0:
		imm.log("%d out of %d modules are not safeseh protected" % (cnt,len(g_modules)))
	else:
		imm.log("All modules are safeseh compiled - good luck !")
	imm.log("--------------------------------------------------------------")
	imm.updateLog()
	
	
def dofind(imm,args,modulefilter):
		filename="find.txt"
		resetfile(filename)
		startaddress=0
		endaddress=2147483647
		skipconsec=0
		cnt=0
		mask=""
		while cnt < len(args):
			if args[cnt]=='-l':
				if cnt < (len(args)-1):
					startaddress=str(args[cnt+1])
					startaddress=startaddress.lower().replace("0x","")
					startaddress="0x" + startaddress
					startaddress=int(startaddress,16)
			if args[cnt]=='-t':
				if cnt < (len(args)-1):
					endaddress=str(args[cnt+1])
					endaddress=endaddress.lower().replace("0x","")
					endaddress="0x" + endaddress
					endaddress=int(endaddress,16)
			if args[cnt]=='-a':
				if cnt < (len(args)-1):
					mask=str(args[cnt+1])
			if args[cnt]=='-c':
					skipconsec=1
			cnt=cnt+1
		if len(args) > 1:
			#convert bytes to bytecode
			cnt=0
			nrfound=0
			nrdone=0
			strb=""
			inp=args[1]
			while cnt < len(inp):
				 try:
					strb=strb+binascii.a2b_hex(inp[cnt]+inp[cnt+1])
					cnt=cnt+2
				 except:
					imm.log("You may have provided an odd length byte string")
					pass
					cnt=cnt+2
			imm.log("Searching for %s, please wait ..." % inp)
			imm.updateLog()
			addys=imm.search( strb )
			imm.log("Search complete")
			imm.updateLog()
			results = []
			results += addys
			for all in results:
				nrfound += 1
			imm.log("Total number of addresses found (before filtering) : %d, now filtering addresses" % nrfound)
			tofile("Found "+str(nrfound)+" addresses pointing to "+inp,filename)
			imm.updateLog()
			if results:
				#sort array
				results.sort()
				#List all addresses
				maskfilt=" "
				cnt=0
				#did we specify a module ?
				if modulefilter != "":
					modulename = getmodnamefromname(modulefilter)
					startaddress=int(getmoduleprop(modulename,"base"))
					endaddress=int(getmoduleprop(modulename,"top"))
				imm.log("Filtering pointers, only showing the ones between 0x%s and 0x%s" % (tohex(startaddress),tohex(endaddress)))
				prevptr=0
				info = ""
				for all in results:
					if (mask=="r"):
						maskfilt="PAGE_READONLY"
					if (mask=="rw"):
						maskfilt="PAGE_READWRITE"
					if (mask=="rx"):
						maskfilt="PAGE_EXECUTE_READ"
					if (mask=="rwx"):
						maskfilt="PAGE_EXECUTE_READWRITE"
					if (mask=="w"):
						maskfilt="PAGE_WRITECOPY"
					if (mask=="wx"):
						maskfilt="PAGE_EXECUTE_WRITECOPY"
					if (mask=="x"):
						maskfilt="PAGE_EXECUTE"
					if (all >= startaddress and all <= endaddress):
						info=addressinfo(all)
					else:
						info="-"
					if info.upper().find(maskfilt.upper()) > 0:
						 #consecutive ?
						if (skipconsec==0) or (all != prevptr+4):
							imm.log("Address : 0x%s : %s" % (tohex(all),info))
							tofile("Location : 0x"+tohex(all)+" ",filename,all)
							imm.updateLog()
						nrdone += 1
					prevptr=all
				imm.log("Done. (Found %d addresses, out of which %d matched specified access mask (%s) and address range)" % (nrfound,nrdone,mask))
		else:
			imm.log("It looks like you forgot to specify the bytes to search for")


def writemodinfo(filename):
  if filename=="":
    cnt=0
    if len(g_modules)==0:
        moduleinfo()
    imm = immlib.Debugger()
    imm.log("----------------------------------------------------------------------------------------------------------------------------------")
    imm.log(" Loaded modules")
    imm.log("----------------------------------------------------------------------------------------------------------------------------------")
    imm.log("  Fixup  |   Base     |    Top     |    Size    | SafeSEH | ASLR  | NXCompat | OS Dll | Version, Modulename & Path")
    imm.log("----------------------------------------------------------------------------------------------------------------------------------")
    safeseh="NO "
    aslr="NO "
    nx="NO "
    rebased="NO "
    osdll="NO "
    for mods in g_modules:
        modrecord=mods.split('\t')
        if modrecord[8]=="1":
            rebased="yes"
        else:
            rebased="NO "
        if modrecord[5]=="1":
            safeseh="yes"
        else:
            safeseh="NO "
        if modrecord[6]=="1":
            aslr="yes"
        else:
            aslr="NO "
        if modrecord[7]=="1":
            nx="yes"
        else:
            nx="NO "
        if modrecord[10]=="1":
            osdll="yes"
        else:
            osdll="NO "
        imm.log("   "+rebased+"   | 0x"+tohex(int(modrecord[2]))+" | 0x"+tohex(int(modrecord[4]))+" | 0x"+tohex(int(modrecord[3]))+" |   "+safeseh+"   |  "+aslr+"  |    "+nx+"   |   "+osdll+"  | "+modrecord[9]+" - "+modrecord[0]+" : "+modrecord[1])
    imm.log("----------------------------------------------------------------------------------------------------------------------------------")
  else:
    cnt=0
    if len(g_modules)==0:
        moduleinfo()
    tofile("----------------------------------------------------------------------------------------------------------------------------------",filename)
    tofile(" Loaded modules",filename)
    tofile("----------------------------------------------------------------------------------------------------------------------------------",filename)
    tofile("  Fixup  |   Base     |    Top     |    Size    | SafeSEH | ASLR  | NXCompat | OS Dll | Version, Modulename & Path",filename)
    tofile("----------------------------------------------------------------------------------------------------------------------------------",filename)
    safeseh="NO "
    aslr="NO "
    nx="NO "
    rebased="NO "
    osdll="NO "
    for mods in g_modules:
        modrecord=mods.split('\t')
        if modrecord[8]=="1":
            rebased="yes"
        else:
            rebased="NO "
        if modrecord[5]=="1":
            safeseh="yes"
        else:
            safeseh="NO "
        if modrecord[6]=="1":
            aslr="yes"
        else:
            aslr="NO "
        if modrecord[7]=="1":
            nx="yes"
        else:
            nx="NO "
        if modrecord[10]=="1":
            osdll="yes"
        else:
            osdll="NO "
        tofile("   "+rebased+"   | 0x"+tohex(int(modrecord[2]))+" | 0x"+tohex(int(modrecord[4]))+" | 0x"+tohex(int(modrecord[3]))+" |   "+safeseh+"   |  "+aslr+"  |    "+nx+"   |   "+osdll+"  | "+modrecord[9]+" - "+modrecord[0]+" : "+modrecord[1],filename)
    tofile("-------------------------------------------------------------------------------------------------------------------",filename)
    tofile("",filename)

"""
Various functions
"""

def tohex(n):
   return "%08X" % n

def toascii(imm,n):
   try:
      asciiequival=binascii.a2b_hex(n)
   except:
      asciiequival=" "
      #print sys.exc_info()[0]
   return asciiequival

def hex2signed(s):
   return struct.unpack('!i', binascii.unhexlify(s))[0]

def hex2long(s):
   return s.atol('FFFFFFFF',16)

def addresstoint(s):
   return int(s, 16)

def tohexbyte(n):
    return "%02X" % n

def u2(x):
   if x & 0x80: # MSB set -> neg.
     return -((~x & 0xff) + 1)
   else:
     return x

def isarray(a):
    try:
        sh = list(a.shape)
    except AttributeError:
        return 0
    try:
        sh[0] = sh[0]+1
        a.shape = sh
    except ValueError:
        return 1
    except IndexError:
        return 1 # ? this is a scalar array
    return 0

"""
Encoding
"""

def doencode(args):
    imm=  immlib.Debugger();
    if len(args) >= 3:
       #args[1] = mode
       #args[2] = opcode to encode
       #args[3] = badchars (optional)
       # or
       #args[1] = mode
       #args[2] = baseaddress of opcode to encode (starts with -b)
       #args[3] = size
	   #args[4] = badchars (optional)
       badchars=[]
       btoencode=args[2]
       #add bad chars provided at command line, if applicable
       if (args[2].lower().startswith("-b")):
           #there must be 4th parameter specifying size
           if len(args) >= 4 and len(args[2]) > 4:
               #read data
               startaddr=args[2]
               startaddr=startaddr[2:len(args[2])]
               startaddr=startaddr.replace('0x','')
               startaddr=startaddr.replace('0X','')
               startloc=addresstoint(startaddr)
               bytes=""
               max=int(args[3])
               cnt=0
               imm.log("Reading %d bytes from 0x%s..." % (max,startaddr))
               imm.updateLog()
               while cnt<max:
                   try:
                     memchar = imm.readMemory(startloc+cnt,1)
                     if len((hex(ord(memchar))).replace('0x',''))==1:
                        memchar2 = hex(ord(memchar)).replace('0x','0')
                     else:
                        memchar2 = hex(ord(memchar)).replace('0x','')
                     bytes=bytes+memchar2
                     cnt=cnt+1
                   except:
                     cnt=cnt+1
                     pass
               btoencode=bytes
               #bad chars specified ?
               if len(args)>=5:
                    srcdata=args[4]
                    maxcnt=len(srcdata)
                    cnt=0
                    while (cnt < maxcnt-1):
                        thischar=srcdata[cnt]+srcdata[cnt+1]
                        badchars.append(addresstoint(thischar))
                        cnt=cnt+2
               imm.log("Done - ready for encoding...")
           else:
               imm.log("You have specified a baseaddress, but forgot to mention the size parameter")
               return

       else:
         if len(args)>=4:
            srcdata=args[3]
            #imm.log("Bad chars specified at command line : %d" % len(srcdata))
            maxcnt=len(srcdata)
            cnt=0
            while (cnt < maxcnt-1):
                thischar=srcdata[cnt]+srcdata[cnt+1]
                badchars.append(addresstoint(thischar))
                #imm.log("Added to bad char list : %d" % addresstoint(thischar))
                cnt=cnt+2
       if args[1].lower()=="ascii":
           ib=0
           while ib<32:
                badchars.append(ib)
                ib=ib+1
           ib=127
           while ib <= 255:
                badchars.append(ib)
                ib=ib+1
           pveencode(args[1],btoencode,badchars)
       if args[1].lower()=="alphanum":
           ib=0
           while ib < 32:
                badchars.append(ib)
                ib=ib+1
           ib=33
           while ib <= 47:
                badchars.append(ib)
                ib=ib+1
           ib=58
           while ib <= 64:
                badchars.append(ib)
                ib=ib+1
           ib=91
           while ib <= 96:
                badchars.append(ib)
                ib=ib+1
           ib=123
           while ib <= 255:
                badchars.append(ib)
                ib=ib+1
           pveencode(args[1],btoencode,badchars)
    else:
        imm.log("Encode : Missing parameters, check syntax !")


def pveencode(type,source,badchars):
  filename="encoded.txt"
  resetfile(filename)
  imm = immlib.Debugger()
  if type=="ascii" or type=="alphanum":
   #see if source is a filename
    if os.path.isfile(source):
	   #read into variable
       imm.log("Reading file %s..." % source)
       srcdata=[]
       srcfile = open(source,"rb")
       content = srcfile.readlines()
       srcfile.close()
       for eachLine in content:
          srcdata += eachLine
       imm.log(" Read %d bytes from file" % len(srcdata))
       cnt=0
       maxcnt=len(srcdata)
       source=""
       hexchar=""
       while (cnt < maxcnt):
          try:
            if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
                hexchar=hex(ord(srcdata[cnt])).replace('0x', '0')
            else:
                hexchar = hex(ord(srcdata[cnt])).replace('0x', '')
            source += hexchar
            cnt=cnt+1
          except:
            imm.log("Unable to process byte %d " % cnt)
            cnt=cnt+1
       imm.log("Bytes read from file : %s " % source)
	#parameter are now bytes
    #make sure total number multiple of 8
    opack=len(source)/8
    npack=opack*8
    if npack != len(source):
       target=((len(source)/8)+1)*8
    else:
       target=len(source)
    while len(source) < target:
       #add null bytes
       source=source+"0"
    nrblocks=len(source)/8
    imm.log("ASCII encoder")
    imm.log("-------------")
    imm.log("4 byte aligned opcode to encode : %s" % source)
    imm.log("Number of bytes to encode : %d" % ((len(source))/2))
    imm.log("Number of encoding blocks : %d (4 byte each)" % nrblocks)
    imm.log("")
    imm.updateLog()
    blockcnt=nrblocks
    encoded=[]
    while blockcnt > 0:
        opcodes=[]
        startpos=(blockcnt*8)-1
        origbytes=source[startpos-7]+source[startpos-6]+source[startpos-5]+source[startpos-4]+source[startpos-3]+source[startpos-2]+source[startpos-1]+source[startpos]
        reversebytes=origbytes[6]+origbytes[7]+origbytes[4]+origbytes[5]+origbytes[2]+origbytes[3]+origbytes[0]+origbytes[1]
        revval=addresstoint(reversebytes)
        twoval=4294967296-revval
        twobytes=tohex(twoval)
        imm.log("Block %d" % (nrblocks-blockcnt+1))
        imm.log("---------")
        imm.log("Opcode to produce : %s%s %s%s %s%s %s%s" % (origbytes[0],origbytes[1],origbytes[2],origbytes[3],origbytes[4],origbytes[5],origbytes[6],origbytes[7]))
        imm.log("         reversed : %s%s %s%s %s%s %s%s" % (reversebytes[0],reversebytes[1],reversebytes[2],reversebytes[3],reversebytes[4],reversebytes[5],reversebytes[6],reversebytes[7]))
        imm.log("                    -----------")
        imm.log("   2's complement : %s%s %s%s %s%s %s%s" % (twobytes[0],twobytes[1],twobytes[2],twobytes[3],twobytes[4],twobytes[5],twobytes[6],twobytes[7]))
        imm.updateLog()
        #for each byte, start with last one first
        bcnt=3
        overflow=0
        while bcnt >= 0:
            currbyte=twobytes[(bcnt*2)]+twobytes[(bcnt*2)+1]
            currval=addresstoint(currbyte)-overflow
            testval=currval/3
            if testval < 32:
                #put 1 in front of byte
                currbyte="1"+currbyte
                currval=addresstoint(currbyte)-overflow
                overflow=1
            else:
                overflow=0
            val1=currval/3
            val2=currval/3
            val3=currval/3
            sumval=val1+val2+val3
            if sumval < currval:
                val3=val3+(currval-sumval)
            #validate / fix badchars
            fixvals=validatebadchars(val1,val2,val3,badchars)
            val1=fixvals[0]
            val2=fixvals[1]
            val3=fixvals[2]
            opcodes.append(tohexbyte(val1))
            opcodes.append(tohexbyte(val2))
            opcodes.append(tohexbyte(val3))
            bcnt=bcnt-1
        imm.log("                    -----------")
        imm.log("                    %s %s %s %s" % (opcodes[9],opcodes[6],opcodes[3],opcodes[0]))
        imm.log("                    %s %s %s %s" % (opcodes[10],opcodes[7],opcodes[4],opcodes[1]))
        imm.log("                    %s %s %s %s" % (opcodes[11],opcodes[8],opcodes[5],opcodes[2]))
        #zero eax
        encoded.append("25")
        encoded.append("4A")
        encoded.append("4D")
        encoded.append("4E")
        encoded.append("55")
        encoded.append("25")
        encoded.append("35")
        encoded.append("32")
        encoded.append("31")
        encoded.append("2A")
        #SUB EAX instructions
        encoded.append("2D")
        encoded.append(opcodes[0])
        encoded.append(opcodes[3])
        encoded.append(opcodes[6])
        encoded.append(opcodes[9])
        encoded.append("2D")
        encoded.append(opcodes[1])
        encoded.append(opcodes[4])
        encoded.append(opcodes[7])
        encoded.append(opcodes[10])
        encoded.append("2D")
        encoded.append(opcodes[2])
        encoded.append(opcodes[5])
        encoded.append(opcodes[8])
        encoded.append(opcodes[11])
        #push eax
        encoded.append("50")
        blockcnt=blockcnt-1
    imm.log("")
    imm.log("Decoder : %d bytes" % len(encoded))
    imm.log("-------------------")
    imm.log("[+] #Perl code - bytes")
    tofile("# Original bytes to decode : " + source,filename)
    tofile("# Original size : " + str(len(source))+" bytes",filename)
    tofile("# Encoded size : " + str(len(encoded))+" bytes",filename)
    tofile("# Perl code",filename)
    imm.log("my $decoder=")
    tofile("my $decoder=",filename)
    dcnt=0
    blockcnt=0
    decoderstring=""
    #26 bytes per block
    while dcnt < len(encoded):
        bcnt=0
        thisline='"'
        if blockcnt >= 26:
           blockcnt=0
        while (bcnt < 5) and (dcnt < len(encoded)) and (blockcnt < 26):
            thisline=thisline+"\\x"+encoded[dcnt]
            bcnt=bcnt+1
            dcnt=dcnt+1
            blockcnt=blockcnt+1
        if dcnt < len(encoded):
            thisline=thisline+'".'
        else:
            thisline=thisline+'";'
        imm.log("%s" % thisline)
        tofile(thisline,filename)
    imm.log("")
    imm.log("[+] #Perl code - ascii characters")
    tofile("",filename)
    tofile("# Perl code - ascii characters",filename)
    dcnt=0
    decoderstring=""
    while dcnt < len(encoded):
        thisbyte=toascii(imm,encoded[dcnt])
        decoderstring=decoderstring+thisbyte
        dcnt=dcnt+1
    imm.log("my $decoder=\"%s\";" % decoderstring)
    tofile("my $decoder=\"" + decoderstring + "\";",filename)
    imm.log("")
    imm.log("Output written to encoded.txt")
    imm.log("")



def validatebadchars(val1,val2,val3,badchars):
    newvals=[]
    imm = immlib.Debugger()
    allok=0
    giveup=0
    type=0
    origval1=val1
    origval2=val2
    origval3=val3
    d1=0
    d2=0
    d3=0
    lastd1=0
    lastd2=0
    lastd3=0
    while allok==0 and giveup==0:
	#check if there are bad chars left
        charcnt=0
        val1ok=1
        val2ok=1
        val3ok=1
        while charcnt < len(badchars):
            if (val1 == badchars[charcnt]):
                val1ok=0
            if (val2 == badchars[charcnt]):
                val2ok=0
            if (val3 == badchars[charcnt]):
                val3ok=0
            charcnt=charcnt+1
        if (val1ok==0) or (val2ok==0) or (val3ok==0):
            allok=0
        else:
            allok=1
        if allok==0:
           #try first by sub 1 from val1 and val2, and add more to val3
           if type==0:
               val1=val1-1
               val2=val2-1
               val3=val3+2
               if (val1<1) or (val2==0) or (val3 > 126):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   type=1
           if type==1:
           #then try by add 1 to val1 and val2, and sub more from val3
               val1=val1+1
               val2=val2+1
               val3=val3-2
               if (val1>126) or (val2>126) or (val3 < 1):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   type=2
           if type==2:
  		       #try by sub 2 from val1, and add 1 to val2 and val3
               val1=val1-2
               val2=val2+1
               val3=val3+1
               if (val1<1) or (val2>126) or (val3 > 126):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   type=3
           if type==3:
	           #try by add 2 to val1, and sub 1 from val2 and val3
               val1=val1+2
               val2=val2-1
               val3=val3-1
               if (val1 > 126) or (val2 < 1) or (val3 < 1):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   type=4
           if type==4:
               if (val1ok==0):
                   val1=val1-1
                   d1=d1+1
               else:
                    #now spread delta over other 2 values
                    if (d1 > 0):
                        val2=val2+1
                        val3=origval3+d1-1
                        d1=d1-1
                    else:
                        val1=0
               if (val1 < 1) or (val2 > 126) or (val3 > 126):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   d1=0
                   type=5
           if type==5:
               if (val1ok==0):
                   val1=val1+1
                   d1=d1+1
               else:
                    #now spread delta over other 2 values
                    if (d1 > 0):
                        val2=val2-1
                        val3=origval3-d1+1
                        d1=d1-1
                    else:
                        val1=255
               if (val1>126) or (val2 < 1) or (val3 < 1):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   val1ok=0
                   val2ok=0
                   val3ok=0
                   d1=0
                   d2=0
                   d3=0
                   type=6
           if type==6:
               if (val1ok==0):
                   val1=val1-1
                   #d1=d1+1
               if (val2ok==0):
                   val2=val2+1
                   #d2=d2+1
               d3=origval1-val1+origval2-val2
               val3=origval3+d3
               #imm.log("%d -> %d -- %d -> %d -- %d -> %d (delta %d)" % (origval1,val1,origval2,val2,origval3,val3,d3))
               if (lastd3==d3) and (d3 > 0):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   giveup=1
               else:
                   lastd3=d3
               if (val1<1) or (val2 < 1) or (val3 > 126):
                   val1=origval1
                   val2=origval2
                   val3=origval3
                   giveup=1
    #check results
	charcnt=0
    val1ok=1
    val2ok=1
    val3ok=1
    val1text="OK"
    val2text="OK"
    val3text="OK"
    while charcnt < len(badchars):
        if (val1 == badchars[charcnt]):
            val1ok=0
            val1text="NOK"
        if (val2 == badchars[charcnt]):
            val2ok=0
            val2text="NOK"
        if (val3 == badchars[charcnt]):
            val3ok=0
            val3text="NOK"
        charcnt=charcnt+1

    if (val1ok==0) or (val2ok==0) or (val3ok==0):
        imm.log("  ** Unable to fix bad char issue !",highlight=1)
        imm.log("     -> Values to check : %s(%s) %s(%s) %s(%s) " % (tohexbyte(origval1),val1text,tohexbyte(origval2),val2text,tohexbyte(origval3),val3text),highlight=1)
        val1=origval1
        val2=origval2
        val3=origval3
    newvals.append(val1)
    newvals.append(val2)
    newvals.append(val3)
    return newvals

"""
Function to get info about a given address
"""
def addressinfo(address):
    imm = immlib.Debugger()
    module = getmodnamefromptr(address)
    if len(g_modules)==0:
        moduleinfo()
    allmodules=g_mods
    tagstr="[Module : "
    modpath=""
    osmodule=""
    extrastring=""
    if module:
        if module == "":
            tagstr=tagstr+"none]"
        else:
            modpath=" - " + getmoduleprop(module,"path")
            osmodule=" * System dll : " + getmoduleprop(module,"systemdll")
            mversion=getmoduleprop(module,"version")
            tagstr=tagstr+module+"]"
            if mversion != "":
               tagstr=tagstr+" v"+mversion
        if getmoduleprop(module,"fixup")=="1":
            tagstr=tagstr+" [Fixup: Yes] "
        else:
            tagstr=tagstr+" [Fixup: ** NO **] "
        if ismodulenosafeseh(module) == 1:
            tagstr=tagstr+" [SafeSEH: ** NO ** - "
        else:
            tagstr=tagstr+" [SafeSEH: Yes - "
        if ismodulenoaslr(module) == 1:
                tagstr=tagstr+"ASLR: ** No (Probably not) **]"
        else:
                tagstr=tagstr+"ASLR : Yes]"
    else:
        tagstr=tagstr+"none]"
    try:
      page   = imm.getMemoryPagebyAddress( address )
      access = page.getAccess( human = True )
      extrastring=" {"+access+"}"+modpath
    except:
       pass
    memTypestr = imm.vmQuery(address)
    if not memTypestr:
		memType = "0x00000000"
    else:
        memType = "0x%08x" % memTypestr[4]
    memType=getMemType(memType)
    return tagstr+"]"+extrastring + " [Memory Type : " + memType + "]" + osmodule

def getMemType(mtype):
  if mtype.upper()=="0X01000000" :
      return "Image"
  elif mtype.upper()=="0X00040000" :
      return "Mapped"
  elif mtype.upper()=="0X00020000" :
      return "Private"
  elif mtype.upper()=="0X00010000" :
      return "Free"
  elif mtype.upper()=="0X00002000" :
      return "Reserved"
  elif mtype.upper()=="0X00001000" :
      return "Committed"
  else:
      return "Unknown"
"""

"""
def addressspec(hexaddr):
    extrastring=""
    nbstring=" ** "
    if (hexaddr[0]=="0" and hexaddr[1]=="0") or (hexaddr[2]=="0" and hexaddr[3]=="0") or (hexaddr[4]=="0" and hexaddr[5]=="0") or (hexaddr[6]=="0" and hexaddr[7]=="0") :
        nbstring=" ** Null byte **"
    if (hexaddr[0]=="0" and hexaddr[1]=="0" and hexaddr[4]=="0" and hexaddr[5]=="0"):
       extrastring=" ** Unicode compatible ** "
       nbstring=" ** Null byte **"
    else:
        if (hexaddr[0]=="0" and hexaddr[1]=="0" and hexaddr[4]=="0" and hexaddr[5]=="1"):
          extrastring=" ** Maybe Unicode compatible **"
          nbstring=" ** Null byte **"
        else:
          #unicode conversion table - ansi
          if (hexaddr[0]=="0" and hexaddr[1]=="0"):
               nbstring=" ** Null byte **"
               transform=0
               almosttransform=0
               twostr=hexaddr[2]+hexaddr[3]
               threestr=hexaddr[4]+hexaddr[5]+hexaddr[6]
               fourstr=hexaddr[4]+hexaddr[5]+hexaddr[6]+hexaddr[7]
               threestr=threestr.upper()
               fourstr=fourstr.upper()
               uniansiconv = [  ["20AC","80"], ["201A","82"],
                 ["0192","83"], ["201E","84"], ["2026","85"],
                 ["2020","86"], ["2021","87"], ["02C6","88"],
                 ["2030","89"], ["0106","8A"], ["2039","8B"],
                 ["0152","8C"], ["017D","8E"], ["2018","91"],
                 ["2019","92"], ["201C","93"], ["201D","94"],
                 ["2022","95"], ["2013","96"], ["2014","97"],
                 ["02DC","98"], ["2122","99"], ["0161","9A"],
                 ["203A","9B"], ["0153","9C"], ["017E","9E"],
                 ["0178","9F"]
               ]
               convbyte=""
               transbyte=""
               ansibytes=""
               for ansirec in uniansiconv:
                  if transform==0:
                    if ansirec[0]==fourstr:
                        convbyte=ansirec[1]
                        transbyte=ansirec[1]
                        transform=1
               if transform==1:
                    extrastring=" ** Unicode ANSI transformed : 00"+twostr+"00"+convbyte
               #possibly close
               ansistring=""
               for ansirec in uniansiconv:
                    if ansirec[0][:3]==threestr:
                      if (transform==0) or (transform==1 and ansirec[1] <> transbyte):
                        convbyte=ansirec[1]
                        ansibytes=ansirec[0]
                        ansistring=ansistring+"00"+twostr+"00"+convbyte+"->00"+twostr+ansibytes+" / "
                        almosttransform=1
               if almosttransform==1:
                   if transform==0:
                      extrastring=" ** Unicode Possible ANSI transformation(s) : " + ansistring
                   else:
                      extrastring=extrastring + " / Alternatives (close pointers) : " + ansistring
    extrastring=extrastring+nbstring
	#see if address only contains limited ascii numbers/chars
    b1=hexaddr[0]+hexaddr[1]
    b2=hexaddr[2]+hexaddr[3]
    b3=hexaddr[4]+hexaddr[5]
    b4=hexaddr[6]+hexaddr[7]
    bi1=addresstoint(b1)
    bi2=addresstoint(b2)
    bi3=addresstoint(b3)
    bi4=addresstoint(b4)
	#numbers : between 48 and 57
	#chars : between 65 and 90, and between 97 and 122
	#just ascii friendly ?
	#between 20 and 126
    if (bi1 >= 32 and bi1 <= 126) and (bi2 >= 32 and bi2 <= 126) and (bi3 >= 32 and bi3 <= 126)  and (bi4 >= 32 and bi4 <= 126):
	    extrastring = extrastring + " - [Ascii printable]"
    if (bi1 >= 48 and bi1 <= 57) or (bi1 >= 65 and bi1 <= 90) or (bi1 >= 97 and bi1 <= 122):
	   if (bi2 >= 48 and bi2 <= 57) or (bi2 >= 65 and bi2 <= 90) or (bi2 >= 97 and bi2 <= 122):
	       if (bi3 >= 48 and bi3 <= 57) or (bi3 >= 65 and bi3 <= 90) or (bi3 >= 97 and bi3 <= 122):
		         if (bi4 >= 48 and bi4 <= 57) or (bi4 >= 65 and bi4 <= 90) or (bi4 >= 97 and bi4 <= 122):
				      extrastring=extrastring + "  - [Num&Alphabet Chars only !]"
    if (bi1==0) and (bi2 >= 32 and bi2 <= 126) and (bi3 == 0) and (bi4 >= 32 and bi4 <= 126):
        extrastring = extrastring + " - [ Ascii printable]"
    if (bi1==0) and (bi2 >= 32 and bi2 <= 126) and (bi3 >= 32 and bi3 <= 126) and (bi4 >= 32 and bi4 <= 126):
        extrastring = extrastring + " - [ Ascii printable - null byte]"
	if (bi1==0) and (bi3==0):
	   if (bi2 >= 48 and bi2 <= 57) or (bi2 >= 65 and bi2 <= 90) or (bi2 >= 97 and bi2 <= 122):
		         if (bi4 >= 48 and bi4 <= 57) or (bi4 >= 65 and bi4 <= 90) or (bi4 >= 97 and bi4 <= 122):
				      extrastring=extrastring + "  - [Num&Alphabet Chars only !]"
    return extrastring

"""
Function to write 2 logfile
"""
def tofile(info,file1,address=0):
    extrastring=""
    tagstr=""
    modpath=""
    if address > 0:
      hexaddr=tohex(address)
      imm = immlib.Debugger()
      if len(g_modules)==0:
	     moduleinfo()
      extrastring=addressspec(hexaddr)
      info=info.replace('\n',' - ')
      # safeseh/aslr marker if we have a module
      module = getmodnamefromptr(address)
      if module:
          if module == "":
            tagstr=tagstr+"none]"
          else:
            mp=getmoduleprop(module,"path")
            modpath=" - " +mp
          if ismodulenosafeseh(module) == 1:
            tagstr=" [SafeSEH: ** NO ** - "
          else:
            tagstr=" [SafeSEH: Yes - "
          try:
            if ismodulenoaslr(module) == 1:
               tagstr=tagstr+"ASLR: ** No (Probably not) **]"
            else:
               tagstr=tagstr+"ASLR : Yes]"
          except:
            tagstr=tagstr+"ASLR : Unable to determine]"
          if getmoduleprop(module,"fixup")=="1":
             tagstr=tagstr+" [Fixup: Yes] "
          else:
             tagstr=tagstr+" [Fixup: ** NO **] "
      try:
         page   = imm.getMemoryPagebyAddress( address )
         access = page.getAccess( human = True )
         extrastring=extrastring + " {"+access+"}"
      except:
         pass
    FILE=open(file1,"a")
    FILE.write(info+extrastring+tagstr+modpath+"\n")
    FILE.close()
    return ""

def resetfile(file1):
    imm = immlib.Debugger()
    try:
       if os.path.exists(file1):
          try:
            os.delete(file1+".old")
          except:
            pass
          try:
            os.rename(file1,file1+".old")
          except:
            try:
                 os.rename(file1,file1+".old2")
            except:
               pass
    except:
        pass
    try:
      FILE=open(file1,"w")
      FILE.write("=" * 80)
      FILE.write("\n  Output generated by pvefindaddr v"+__VERSION__+"\n")
      FILE.write("  corelanc0d3r - http://www.corelan.be:8800\n")
      FILE.write("=" * 80)
      osver=imm.getOsVersion()
      osrel=imm.getOsRelease()
      FILE.write("\n  OS : " + osver + ", release " + osrel+"\n")
      FILE.write("=" * 80)
      FILE.write("\n  " + datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S") + "\n")
      FILE.write("=" * 80)
      FILE.write("\n")
      FILE.close()
    except:
      pass
    return ""

def IsNumber(value):
  return str(value).replace(".", "").replace("-", "").replace(",","").isdigit()

"""
Metasploit-compatible pattern
"""
def pattern_create(size):
    char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    char2="abcdefghijklmnopqrstuvwxyz"
    char3="0123456789"
    charcnt=0
    pattern=""
    max=int(size)
    for ch1 in char1:
       for ch2 in char2:
           for ch3 in char3:
              if charcnt<max:
                pattern=pattern+ch1
                charcnt=charcnt+1
              if charcnt<max:
                pattern=pattern+ch2
                charcnt=charcnt+1
              if charcnt<max:
                pattern=pattern+ch3
                charcnt=charcnt+1
    return pattern

"""
Calculate offset in Metasploit compatible pattern
"""
def pattern_offset(searchpat,size,imm):
        mspattern=""
        patsize=int(size)
        mspattern=pattern_create(size)
        if len(searchpat)==4:
           ascipat2=searchpat
           imm.log("Looking for %s in pattern of %d bytes" % (ascipat2,patsize))
           if ascipat2 in mspattern:
              patpos = mspattern.find(ascipat2)
              imm.log(" - Pattern %s found in Metasploit pattern at position %d" % (ascipat2,patpos),highlight=1)
           else:
              imm.log(" - Pattern %s not found in Metasploit pattern" % ascipat2)
        if len(searchpat)==8:
              searchpat="0x"+searchpat
        if len(searchpat)==10:
              hexpat=searchpat
              ascipat3=toascii(imm,hexpat[8]+hexpat[9])+toascii(imm,hexpat[6]+hexpat[7])+toascii(imm,hexpat[4]+hexpat[5])+toascii(imm,hexpat[2]+hexpat[3])
              imm.log("Looking for %s in pattern of %d bytes" % (ascipat3,patsize))
              if ascipat3 in mspattern:
                 patpos = mspattern.find(ascipat3)
                 imm.log(" - Pattern %s (%s) found in Metasploit pattern at position %d" % (ascipat3,hexpat,patpos),highlight=1)
              else:
                 #maybe it's reversed
                 ascipat4=toascii(imm,hexpat[2]+hexpat[3])+toascii(imm,hexpat[4]+hexpat[5])+toascii(imm,hexpat[6]+hexpat[7])+toascii(imm,hexpat[8]+hexpat[9])
                 imm.log("Looking for %s in pattern of %d bytes" % (ascipat4,patsize))
                 if ascipat4 in mspattern:
                   patpos = mspattern.find(ascipat4)
                   imm.log(" - Pattern %s (%s reversed) found in Metasploit pattern at position %d" % (ascipat4,hexpat,patpos),highlight=1)
                 else:
                   imm.log(" - Pattern %s not found in Metasploit pattern" % ascipat4)

"""
Compare shellcode in memory with data from a file
"""
def memcompare(imm,location,srcdata,comparetable,sctype):
    filename="compare.txt"
    loc = location.replace("0x","")
    loc = loc.replace("0X","")
    imm.log("   * Reading memory at location : 0x%s " % location,address=addresstoint(location),highlight=1)
    tofile("* Reading memory at location 0x" + location,filename)
    imm.updateLog()
    memloc=addresstoint(loc)
	#read memory at that location and compare with bytes in array
    maxcnt=len(srcdata)
    brokenbytes=[]
    filelines=[]
    memlines=[]
    nrokbytes=0
    nrbrokenbytes=0
    cnt=0
    linecount=0
    firstcorruption=0
    while (cnt < maxcnt):
      #group per 8 bytes for display purposes
      btcnt=0
      hexstr=""
      thislinemem=""
      thislinefile=""
      while ((btcnt < 8) and (cnt < maxcnt)):
        try:
           if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
             thischar=hex(ord(srcdata[cnt])).replace('0x','0')
             hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
           else:
             thischar=hex(ord(srcdata[cnt])).replace('0x','')
             hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
           #thischar = hex(ord(srcdata[cnt])).replace('0x','')
           #hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
           hexstr += hexchar
           memchar = imm.readMemory(memloc+cnt,1)
           #compare byte in memory with byte in file
           if len((hex(ord(memchar))).replace('0x',''))==1:
               memchar2 = hex(ord(memchar)).replace('0x','0')
           else:
               memchar2 = hex(ord(memchar)).replace('0x','')
           thislinefile=thislinefile+thischar
           if (memchar2 == thischar):
              nrokbytes=nrokbytes+1
              thislinemem=thislinemem+thischar
           else:
              nrbrokenbytes=nrbrokenbytes+1
              thislinemem=thislinemem+"--"
              if (firstcorruption==0):
                firstcorruption=cnt
              imm.log("     Corruption at position %d : Original byte : %s - Byte in memory : %s" % (cnt,thischar,memchar2))
              tofile("   Corruption at position " +str(cnt)+" : Original byte : " + thischar + " - Byte in memory : " + memchar2,filename)
           btcnt=btcnt+1
           cnt=cnt+1
        except:
           imm.log("   ******* Error processing byte %s " % cnt)
           tofile("   ******* Error processing byte " + str(cnt),filename)
           imm.updateLog()
           cnt=cnt+1
           btcnt=btcnt+1
           continue
      filelines += thislinefile
      memlines += thislinemem

    if (nrokbytes == maxcnt):
        imm.log("     -> Hooray, %s shellcode unmodified" % sctype,focus=1, highlight=1)
        tofile("     -> Hooray, " + sctype + " shellcode unmodified",filename)
        comparetable.add(0,["0x%s"%(location),'Unmodified',sctype])
    else:
        imm.log("     -> Only %d original bytes of %s code found !" % (nrokbytes,sctype))
        tofile("     -> Only " + str(nrokbytes)+" original bytes found",filename)
        comparetable.add(0,['0x%s'%(location),'Corruption after %d bytes'%(firstcorruption),sctype])
        lcnt=0
        lmax = len(filelines)
        imm.log("      +-----------------------+-----------------------+")
        tofile("      +-----------------------+-----------------------+",filename)
        imm.log("      | FILE                  | MEMORY                |")
        tofile("      | FILE                  | MEMORY                |",filename)
        imm.log("      +-----------------------+-----------------------+")
        tofile("      +-----------------------+-----------------------+",filename)
        while (lcnt < lmax):
            #read in pairs of 8 bytes
            bytecnt=0
            logline1="|"
            logline2=""
            while ((lcnt < lmax) and (bytecnt < 16)):
                pair=0
                while ((lcnt < lmax) and (pair < 2)):
                   logline1=logline1+filelines[lcnt]
                   logline2=logline2+memlines[lcnt]
                   pair=pair+1
                   lcnt=lcnt+1
                   bytecnt=bytecnt+1
                logline1=logline1+"|"
                logline2=logline2+"|"
            if (bytecnt < 16):
                while (bytecnt < 16):
                   logline1=logline1+" "
                   logline2=logline2+" "
                   bytecnt=bytecnt+1
                logline1=logline1+"|"
                logline2=logline2+"|"
            imm.log("      %s%s" % (logline1,logline2))
            tofile("      "+logline1+logline2,filename)
        imm.log("      +-----------------------+-----------------------+")
        tofile("      +-----------------------+-----------------------+",filename)
        imm.log("")

def tocontent(memcontent):
    mycontent=""
    for membyte in memcontent:
        newbyte=hex(ord(membyte)).replace('0x','')
        if(len(newbyte)==1):
            mycontent=mycontent+"0"+newbyte
        else:
            mycontent=mycontent+newbyte
    if (len(mycontent)==8):
        newcontent=mycontent[6]+mycontent[7]+mycontent[4]+mycontent[5]+mycontent[2]+mycontent[3]+mycontent[0]+mycontent[1]
       	mycontent=newcontent
    return mycontent

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
  MAIN APPLICATION
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
def main(args):
    imm = immlib.Debugger()
    if len(args) == 0:
        usage(imm)
        return "Error: No arguments - read the usage text for more info"
    results = []
    filter=""
    nrfound=0
    g_typeofsploit=0
    g_jumpreg=""
    g_address=""
    g_offset=0
    g_regpos=0
    g_regoff=""
    imm.log("")
    imm.updateLog()
    imm.log("")
    imm.log("")
    imm.updateLog()
    """
    Parse generic arguments
    """
    nonull=0
    noos=0
    modulefilter=""
    if len(args) > 1:
        cnt=1
        while cnt < len(args):
            if args[cnt]=='-m':
                if cnt < (len(args)-1):
                    modulefilter=args[cnt+1]
            if args[cnt]=='-n':
                nonull=1
            if args[cnt]=='-o':
                noos=1
            cnt=cnt+1

    """
	List all modules that are not safeseh protected
	"""
    if (args[0] == "nosafeseh" or args[0] == "safeseh"):
        found=0
        if len(g_modules)==0:
            moduleinfo()
        imm.log("Safeseh unprotected modules : ")
        for mods in g_modules:
            modrecord=mods.split('\t')
            if (modrecord[5]=="0"):
              found=1
              mzbase=int(modrecord[2])
              mztop=int(modrecord[4])
              path=modrecord[1]
              np=modrecord[0]
              extra=""
              if (modrecord[8]=="1"):
                  extra=" - !BaseFixup!"
              else:
                  extra=""
              imm.log(" * 0x%08x - 0x%08x : %s %s (%s)" % (mzbase,mztop,np,extra,path),highlight=1)
        imm.log("")
        if found==0:
           imm.log("All loaded modules are safeseh protected - good luck",highlight=1)
        imm.log("")

    """
    List all modules that are not safeseh or asrl aware
    """
    if args[0] == "nosafesehaslr" or args[0] == "safesehaslr":
		getnosafesehaslr(imm,0)



    """
    List all modules that are not aslr aware
    """
    if (args[0] == "noaslr" or args[0] == "aslr"):
        found=0
        if len(g_modules)==0:
            moduleinfo()
        imm.log("Loaded modules - ASLR protection status : ")
        imm.log("-----------------------------------------")
        for mods in g_modules:
            modrecord=mods.split('\t')
            extra=""
            if (modrecord[8]=="1"):
                extra=" - !BaseFixup!"
            else:
                extra=""
            if (modrecord[6]=="0"):
              found=1
              mzbase=int(modrecord[2])
              mztop=int(modrecord[4])
              path=modrecord[1]
              np=modrecord[0]
              imm.log(" * 0x%08x - 0x%08x : %s %s (%s) : NO ASLR" % (mzbase,mztop,np,extra,path),highlight=1)
              imm.updateLog()
            else:
              mzbase=int(modrecord[2])
              mztop=int(modrecord[4])
              path=modrecord[1]
              np=modrecord[0]
              imm.log(" * 0x%08x - 0x%08x : %s %s (%s) : ASLR ENABLED" % (mzbase,mztop,np,extra,path))
              imm.updateLog()
        imm.log("")
        if found==0:
           imm.log("All loaded modules are aslr aware - good luck",highlight=1)
        imm.log("")

    """
    Search for pop pop ret (mostly used in SEH based overflows. Only addresses in modules that are not safeseh protected
	and not subject to aslr will be listed, unless you specify your own module name.
    """
    if args[0] == "a":
        if modulefilter <> "":
            noos=0
        imm.log("-------------------------------------------------------------------")
        imm.log("Search for pop pop ret alternative (add esp 8,ret) started ")
        imm.log("Search in non-safeseh, non-aslr modules and non-fixup modules only")
        imm.log("Please wait...")
        imm.log("-------------------------------------------------------------------")
        filename="ppralternative.txt"
        resetfile(filename)
        writemodinfo(filename)
        getnosafesehaslr(imm,1)
        imm.log("--------------------------------------------------------------")
        opcodej=["\x83\xc4\x08\xc3","\x83\xc4\x08\xc2",#add esp,8 +ret
		"\x94\x8d\x40\x08\x8b\x10\x94\xc3", #XCHG EAX,ESP#LEA EAX,[EAX+8]#MOV EDX,EAX#XCHG EAX,ESP#RETN
		"\x94\x8d\x40\x08\x8b\x10\x94\xc2"]
        for op in opcodej:
          addys=imm.search(op)
          results += addys
          for ad1 in addys:
            module = getmodnamefromptr(ad1)
            if not module:
                module = "none"
            else:
                if module=="":
                    module = "none"
                else:
                    module = module.lower()
            if module.upper().find(modulefilter.upper()) >= 0 and getmoduleprop(module,"fixup")=="0" and getmoduleprop(module,"aslr")=="0" and getmoduleprop(module,"safeseh")=="0":
                if (noos==0) or (noos==1 and isosmodule(module)==0):
                    aspec=addressspec(tohex(ad1)).upper()
                    if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                      try:
                           page = imm.getMemoryPagebyAddress( ad1 )
                           access = page.getAccess( human = True )
                           hexaddr=tohex(ad1)
                           op = imm.Disasm( ad1 )
                           opstring=op.getDisasm()
                           imm.log("Found %s at 0x%08x [%s] Access: (%s) " % (opstring, ad1, module, access), address = ad1,highlight=1)
                           tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                           nrfound+=1
                      except:
                           pass
        imm.log("Search complete")
        imm.log("Output written to "+filename)
        if results:
            imm.log("Found %d address(es) in non-safeseh protected and non-aslr aware modules, out of %d addresses" % (nrfound,len(results)))
            tofile("See if one of these addresses is followed by RET !",filename)
            imm.log("See if one of these addresses is followed by RET !")
            return "Found %d address(es) (Check the Log Windows for details)" % nrfound
        else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
        imm.log("--------------------------------------------------------------")
        return "Done - check %s" % filename


    """
    Search for pop pop ret (mostly used in SEH based overflows)
    """
    if args[0] == "p" or args[0]=="p1" or args[0]=="p2" or args[0] == "xp" or args[0]=="xp1" or args[0]=="xp2":
        imm.log("------------------------------------------------------------------")
        if args[0] == "p" or args[0]=="p1" or args[0]=="p2":
          imm.log("Search for pop XX pop XX ret combinations")
        if args[0] == "xp" or args[0]=="xp1" or args[0]=="xp2":
          imm.log("Search for xor + pop XX pop XX ret combinations (sehop)")
        imm.log("------------------------------------------------------------------")
        nosafeseh=1
        noaslr=0
        filename="ppr.txt"
        if args[0] == "p1" or args[0] == "xp1":
            noaslr=1
            filename="ppr1.txt"
        if args[0] == "p2" or args[0] == "xp2":
            noaslr=0
            nosafeseh=0
            filename="ppr2.txt"
        if args[0].lower().find("x") > -1:
               filename="x" + filename
        resetfile(filename)
        writemodinfo(filename)
        shownosafeseh()
        offsets = [ "", " 04"," 08"," 0c"," 10"," 12"," 1C"]
        returns= ["ret"]
        regs=["eax","ebx","ecx","edx","esi","edi","esp","ebp"]
        filter=""
        if len(args) > 1:
          cnt=1
          while cnt < len(args):
              if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    filter=args[cnt+1]
              cnt=cnt+1
          if modulefilter <> "":
            noos=0
        if nosafeseh==1:
            imm.log("[+] Excluding safeseh protected modules")
        else:
            imm.log("[+] Including safeseh protected modules")
        if noaslr==1:
            imm.log("[+] Excluding ASLR enabled modules")
        else:
            imm.log("[+] Including ASLR enabled modules")
        if noos==1:
            imm.log("[+] Excluding modules from Windows folder")
        else:
            imm.log("[+] Including modules from Windows folder")
        if nonull==1:
            imm.log("[+] Excluding pointers with null bytes")
        else:
            imm.log("[+] Including pointers with null bytes")
        if modulefilter <> "":
            imm.log("[+] Only showing pointers from module %s" % modulefilter)
        imm.updateLog()
        results=[]
        imm.log("Launching search, please wait...")
        for r1 in regs:
         for r2 in regs:
           for roffset in offsets:
            op = "pop "+r1+"\npop "+r2+"\nret "+roffset
            op=op.strip()
            if op.find(filter) >= 0:
                addys=imm.search( imm.assemble (op) )
                results += addys
                imm.log(" * %d pointers found ending with RET%s, now filtering results..." % (len(addys),roffset))
                for ad1 in addys:
                    module = getmodnamefromptr(ad1)
                    if not module:
                        module = "none"
                    else:
                        if module=="":
                            module = "none"
                        else:
                            module = module.lower()
                    if module.upper().find(modulefilter.upper()) >= 0:
                        if (noaslr==0) or (noaslr==1 and getmoduleprop(module,"aslr")=="0" and getmoduleprop(module,"fixup")=="0"):
                            if (nosafeseh==0) or (nosafeseh==1 and getmoduleprop(module,"safeseh")=="0"):
                                if (noos==0) or (noos==1 and isosmodule(module)==0):
                                   aspec=addressspec(tohex(ad1)).upper()
                                   if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                                      if args[0] == "xp" or args[0]=="xp1" or args[0]=="xp2":
                                         #only add if ppr is preceeded with a xor reg,reg operation
                                         opstart=imm.DisasmBackward(ad1,1)
                                         opadstart=opstart.getAddress()
                                         opstring=opstart.getDisasm()
                                         if opstring.upper().find("XOR") >= 0:
                                               #xor samereg,samereg ?
                                               xorfields=opstring.lower().split(' ')
                                               if len(xorfields) > 1:
                                                 xorregs = xorfields[1].split(',')
                                                 if len(xorregs) > 1:
                                                    if xorregs[0].replace(" ","") == xorregs[1].replace(" ",""):
                                                      tofile("Found "+opstring.lower() + " - " + op + " at 0x" + tohex(opadstart)+" ["+module+"]",filename,opadstart)
                                                      nrfound+=1
                                      else:
                                        tofile("Found "+op+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                                        nrfound+=1
                imm.updateLog()
        imm.log("Search complete")
        imm.log("Output written to "+filename)
        if results:
            imm.log("Found %d valid address(es) (out of a total of %d addresses)" % (nrfound,len(results)))
            return "Found %d address(es) (Check the Log Windows for details)" % nrfound
        else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
        imm.log("--------------------------------------------------------------")
        return "Done - check %s" % filename

    if args[0] == "pdep":
        imm.log("----------------------------------------------------------------------------------------------------")
        imm.log("Search for dep bypass instructions such as p/p/pop esp / ret combinations started - please wait...")
        imm.log("----------------------------------------------------------------------------------------------------")
        filename="pdep.txt"
        resetfile(filename)
        writemodinfo(filename)
        if len(g_modules)==0:
            moduleinfo()
        shownosafeseh()
        searchreg=""
        offsets = [ " 04"," 08"," 0c"," 10"]
        ppr = []
        aregs=["eax","ebx","ecx","edx","esi","edi","ebp"]
        if len(args) > 1:
          cnt=1
          while cnt < len(args):
              if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    searchreg=args[cnt+1]
              cnt=cnt+1
          if modulefilter <> "":
            noos=0
        for areg in aregs:
            for breg in aregs:
                ppr.append("pop "+areg+"\npop "+breg+"\n pop esp\n ret")
        for op in ppr:
	      #filter defined
          filter=searchreg
          if op.find(filter) >= 0:
		     #first search for normal ppr
            addys=imm.search( imm.assemble (op) )
            results += addys
            for ad1 in addys:
              module = getmodnamefromptr(ad1)
              if not module:
                  module = "none"
              else:
                  if module=="":
                    module = "none"
                  else:
                    module = module.lower()
              if modulefilter == "":
                 if ismodulenosafeseh(module) == 1 and getmoduleprop(module,"fixup")=="0":
                   if (noos==0) or (noos==1 and isosmodule(module)==0):
                    aspec=addressspec(tohex(ad1)).upper()
                    if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                      tofile("Found "+op+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                      nrfound+=1
                 else:
                    if (noos==0) or (noos==1 and isosmodule(module)==0):
                      aspec=addressspec(tohex(ad1)).upper()
                      if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                        tofile("Found "+op+" at 0x" + tohex(ad1)+" ["+module+"] ** SafeSEH protected **",filename,ad1)
                        nrfound+=1
              else:
                 if module.find(modulefilter) >= 0:
                  if (noos==0) or (noos==1 and isosmodule(module)==0):
                        aspec=addressspec(tohex(ad1)).upper()
                        if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                         tofile("Found "+op+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                         nrfound+=1
            #now also search for ret+offsets
            for ofs in offsets:
              addys=imm.search( imm.assemble (op+ofs) )
              results += addys
              for ad1 in addys:
                module = getmodnamefromptr(ad1)
                if not module:
                  module = "none"
                else:
                  if module=="":
                    module = "none"
                  else:
                    module = module.lower()
                if modulefilter == "":
                  #only show addresses from non-safeseh protected modules
                  if ismodulenosafeseh(module) == 1 and getmoduleprop(module,"fixup")=="0":
                    if (noos==0) or (noos==1 and isosmodule(module)==0):
                      aspec=addressspec(tohex(ad1)).upper()
                      if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                        tofile("Found "+op+ofs+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                        nrfound+=1
                  else:
                     if (noos==0) or (noos==1 and isosmodule(module)==0):
                       aspec=addressspec(tohex(ad1)).upper()
                       if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                        tofile("Found "+op+ofs+" at 0x" + tohex(ad1)+" ["+module+"] ** SafeSEH protected ** ",filename,ad1)
                        nrfound+=1
                else:
                    if module.find(modulefilter) >= 0:
                      if (noos==0) or (noos==1 and isosmodule(module)==0):
                        aspec=addressspec(tohex(ad1)).upper()
                        if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                         tofile("Found "+op+ofs+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                         nrfound+=1
        imm.log("Search complete")
        imm.log("Output written to "+filename)
        if results:
            imm.log("Found %d address(es) in non-safeseh protected modules, out of %d addresses" % (nrfound,len(results)))
            return "Found %d address(es) (Check the Log Windows for details)" % nrfound
        else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
        imm.log("--------------------------------------------------------------")
        return "Done - check %s" % filename


    """
    Function that looks for jump/call/push addresses (mostly used in direct RET BOF)
    """
    if args[0] == "j":
        filename="j.txt"
        resetfile(filename)
        writemodinfo(filename)
        searchreg="esp"
        if len(args) > 1:
          cnt=1
          while cnt < len(args):
              if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    searchreg=args[cnt+1]
              cnt=cnt+1
          if modulefilter <> "":
            noos=0
          imm.log("------------------------------------------------------------------")
          imm.log("Search for jmp/call/push ret combinations started - please wait...")
          imm.log("------------------------------------------------------------------")
          opcodej=["jmp "+searchreg,"call "+searchreg,"push "+searchreg+"\n ret","push "+searchreg+"\n ret 4","push "+searchreg+"\n ret 8","push "+searchreg+"\n ret 0c"]
          regs=["eax","ebx","ecx","edx","esi","edi"]
          for thisreg in regs:
            opcodej.append("push "+searchreg+"\n pop "+thisreg+"\n jmp "+thisreg)
            opcodej.append("push "+searchreg+"\n pop "+thisreg+"\n call "+thisreg)
            if thisreg.upper()<>searchreg.upper():
                opcodej.append("mov "+thisreg+","+searchreg+"\n jmp "+thisreg)
                opcodej.append("mov "+thisreg+","+searchreg+"\n call "+thisreg)
                opcodej.append("mov "+thisreg+","+searchreg+"\n push "+thisreg+"\n ret")
          for opj in opcodej:
              imm.log("-> Searching for %s" % (opj),highlight=1)
              imm.updateLog()
              addys=imm.search( imm.assemble (opj) )
              results += addys
              for ad1 in addys:
                module = getmodnamefromptr(ad1)
                if not module:
                  module = "none"
                else:
                  if module=="":
                    module = "none"
                  else:
                    module = module.lower()
                isfixup=getmoduleprop(module,"fixup")
                isaslr=getmoduleprop(module,"aslr")
                #reset fixup/aslr values if you specified a module name
                if modulefilter <> "" and module.upper().find(modulefilter.upper()) >= 0:
                    isfixup="0"
                    isaslr="0"
                if module.upper().find(modulefilter.upper()) >= 0 and isfixup =="0" and isaslr=="0":
                  if (noos==0) or (noos==1 and isosmodule(module)==0):
                        aspec=addressspec(tohex(ad1)).upper()
                        if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                           #page   = imm.getMemoryPagebyAddress( ad1 )
                           #access = page.getAccess( human = True )
                           #hexaddr=tohex(ad1)
                           #imm.log("Found %s at 0x%08x [%s] Access: (%s) " % (opj, ad1, module, access), address = ad1)
                           tofile("Found "+opj+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                           imm.updateLog()
                           nrfound+=1
          imm.log("Search complete")
          imm.log("Output written to "+filename)
          if results:
            imm.log("Found %d address(es)" % nrfound)
            return "Found %d address(es) (Check the Log Windows for details)" % nrfound
          else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
          imm.log("--------------------------------------------------------------")

        else:
          usage(imm)
          return "Error: Please provide register and optional module name"

    """
    Function that looks for jump/call/push addresses (mostly used in direct RET BOF)
    """
    if args[0] == "jp":
        if len(args) > 1:
          imm.log("------------------------------------------------------------------------------------------------")
          imm.log("Search for jmp/call/push ret combinations + pointers to these address started - please wait...")
          imm.log("------------------------------------------------------------------------------------------------")
          cnt=1
          while cnt < len(args):
              if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    searchreg=args[cnt+1]
              cnt=cnt+1
          if modulefilter <> "":
            noos=0
          opcodej=["jmp "+searchreg,"call "+searchreg,"push "+searchreg+"\n ret","push "+searchreg+"\n ret 4","push "+searchreg+"\n ret 8","push "+searchreg+"\n ret 0c"]
          filename="jp.txt"
          resetfile(filename)
          writemodinfo(filename)
          for opj in opcodej:
              addys=imm.search( imm.assemble (opj) )
              results += addys
              for ad1 in addys:
                module = getmodnamefromptr(ad1)
                if not module:
                  module = "none"
                else:
                  if module=="":
                    module = "none"
                  else:
                    module = module.lower()
                if module.find(modulefilter) >= 0 and getmoduleprop(module,"fixup")=="0":
                  #page   = imm.getMemoryPagebyAddress( ad1 )
                  #access = page.getAccess( human = True )
                  #now look for a pointer to that address
                  #imm.log("Found %s at 0x%08x [%s] Access: (%s)" % (opj, ad1, module, access), address = ad1)
                  thisadr=tohex(ad1)
                  try:
                    b4 = thisadr[0]+thisadr[1]
                    b3 = thisadr[2]+thisadr[3]
                    b2 = thisadr[4]+thisadr[5]
                    b1 = thisadr[6]+thisadr[7]
                    b=binascii.a2b_hex(b1)+binascii.a2b_hex(b2)+binascii.a2b_hex(b3)+binascii.a2b_hex(b4)
                    #imm.log("Looking for pointers to %s" % b)
                    addys2=imm.search(b)
                    for ad2 in addys2:
                      module = getmodnamefromptr(ad2)
                      if not module:
                          module = "none"
                      else:
                       if module <> "":
                        module = module.lower()
                        page   = imm.getMemoryPagebyAddress( ad2 )
                        access = page.getAccess( human = True )
                        imm.log("Found %s at 0x%08x [%s] Access: (%s)" % (opj, ad1, module, access), address = ad1)
                        imm.log("  -> Found pointer to %s at 0x%08x (%s) - Access: (%s)" % (opj, ad2, module,access), address = ad2)
                        tofile("Found "+opj+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                        tofile("  -> Found pointer to " + opj + " at 0x"+tohex(ad2)+" ["+module+"]",filename,ad2)
                        nrfound+=1
                    b=binascii.a2b_hex(b2)+binascii.a2b_hex(b3)+binascii.a2b_hex(b4)
                    #imm.log("Looking for pointers to %s" % b)
                    addys2=imm.search(b)
                    for ad2 in addys2:
                      ad2=ad2-1
                      module = getmodnamefromptr(ad2)
                      if not module:
                          module = "none"
                      else:
                       if module <> "":
                        page   = imm.getMemoryPagebyAddress( ad2 )
                        access = page.getAccess( human = True )
                        imm.log("Found %s at 0x%08x [%s] Access: (%s)" % (opj, ad1, module, access), address = ad1)
                        imm.log("  -> Found possible pointer to %s at 0x%08x (%s) - Access: (%s)" % (opj, ad2, module,access), address = ad2)
                        tofile("Found "+opj+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                        tofile("  -> Found 'close' pointer to " + opj+" at 0x"+tohex(ad2)+" ["+module+"]",filename,ad2)
                        nrfound+=1
                  except:
                    imm.log("  Unable to search for pointers (due to null byte)")
          imm.log("Search complete")
          imm.log("Output written to "+filename)
          if results:
            imm.log("Found %d pointer(s)" % nrfound)
            return "Found %d address(es) (Check the Log Windows for details)" % nrfound
          else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
          imm.log("--------------------------------------------------------------")

        else:
          usage(imm)
          return "Error: Please provide register and optional module name"



    """
    Function that looks for a jump to a register+offset
    """
    if args[0] == "jo":
        filename="jo.txt"
        resetfile(filename)
        writemodinfo(filename)
        opsearch = []
        minoffset=-101
        maxoffset=101
        if len(args) > 1:
          cnt=1
          while cnt < len(args):
              if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    searchreg=args[cnt+1].upper()
              if args[cnt]=='-l':
                if cnt < (len(args)-1):
                    if IsNumber(args[cnt+1]):
                      minoffset=int(args[cnt+1])
              if args[cnt]=='-t':
                if cnt < (len(args)-1):
                    if IsNumber(args[cnt+1]):
                       maxoffset=int(args[cnt+1])
              cnt=cnt+1
          if modulefilter <> "":
            noos=0
          imm.log("---------------------------------------------------------------------")
          imm.log("Search for jump to reg + offset combinations started - please wait...")
          imm.log("---------------------------------------------------------------------")
          #arg1 = reg
          targetreg=searchreg
          allop=[
          "EAX 0xff0x500x??",   #call dword ptr EAX
          "ECX 0xff0x510x??",           #               ECX
          "EDX 0xff0x520x??",           #               EDX
          "EBX 0xff0x530x??",           #               EBX
          "EBP 0xff0x550x??",           #               EBP
          "ESI 0xff0x560x??",           #               ESI
          "EDI 0xff0x570x??",           #               EDI
          "EAX 0xff0x580x??",           #               far EAX
          "ESP 0xff0x540x240x??",       #               ESP
          "EAX 0xff0x600x240x??",            #jmp dword ptr eax
          "ECX 0xff0x610x240x??",            #jmp dword ptr ecx
          "EDX 0xff0x620x240x??",            #jmp dword ptr edx
          "EBX 0xff0x630x240x??",            #jmp dword ptr ebx
          "ESP 0xff0x640x240x??",            #jmp dword ptr esp
          "EBP 0xff0x650x240x??",             #jmp dword ptr ebp
          "ESI 0xff0x660x240x??",            #jmp dword ptr esi
          "EDI 0xff0x670x240x??",            #jmp dword ptr edi

          "EAX 0xff0x700x240x??0xc3",         #push dword ptr eax
          "EAX 0xff0x700x240x??0xc2",         #push dword ptr eax
          "ECX 0xff0x710x240x??0xc3",            #push dword ptr ecx
          "ECX 0xff0x710x240x??0xc2",            #push dword ptr ecx
          "EDX 0xff0x720x240x??0xc3",            #push dword ptr edx
          "EDX 0xff0x720x240x??0xc2",            #push dword ptr edx
          "EBX 0xff0x730x240x??0xc3",            #push dword ptr ebx
          "EBX 0xff0x730x240x??0xc2",            #push dword ptr ebx
          "ESP 0xff0x740x240x??0xc3",            #push dword ptr esp
          "ESP 0xff0x740x240x??0xc2",            #push dword ptr esp
          "EBP 0xff0x750x??0xc3",             #push dword ptr ebp
          "EBP 0xff0x750x??0xc2",             #push dword ptr ebp
          "ESI 0xff0x760x240x??0xc3",            #push dword ptr esi
          "ESI 0xff0x760x240x??0xc2",            #push dword ptr esi
          "EDI 0xff0x770x240x??0xc3",            #push dword ptr edi
          "EDI 0xff0x770x240x??0xc2",            #push dword ptr edi
          "EAX 0xff0x680x??"                 #jmp far dword ptr eax
          ]

          posop=[
          "EAX 0x830xc00x??0x500xc3",        #add eax + push + ret
          "EAX 0x810xc00x??0x000x000x000x500xc3",
          "EAX 0x830xc00x??0x500xc2",		 #add eax + push + ret n
          "EAX 0x810xc00x??0x000x000x000x500xc2",
          "ECX 0x830xc10x??0x510xc3",        #add ecx + push + ret
          "ECX 0x810xc10x??0x000x000x000x510xc3",
          "ECX 0x830xc10x??0x510xc2",		 #add ecx + push + ret n
          "ECX 0x810xc10x??0x000x000x000x510xc2",
          "EDX 0x830xc20x??0x520xc3",        #add edx + push + ret
          "EDX 0x810xc20x??0x000x000x000x520xc3",
          "EDX 0x830xc20x??0x520xc2",		 #add edx + push + ret n
          "EDX 0x810xc20x??0x000x000x000x520xc3",
          "EBX 0x830xc30x??0x530xc3",        #add ebx + push + ret
          "EBX 0x810xc30x??0x000x000x000x530xc3",
          "EBX 0x830xc30x??0x530xc2",		 #add ebx + push + ret n
          "EBX 0x810xc30x??0x000x000x000x530xc3",
          "ESP 0x830xc40x??0x540xc3",            #add esp + push + ret
          "ESP 0x810xc40x??0x000x000x000x540xc3",
          "ESP 0x830xc40x??0x540xc2",		     #add esp + pups + ret n
          "ESP 0x810xc40x??0x000x000x000x540xc2",
          "EBP 0x830xc50x??0x550xc3",        #add ebp + push + ret
          "EBP 0x810xc50x??0x000x000x000x550xc3",
          "EBP 0x830xc50x??0x550xc2",		 #add ebp + push + ret n
          "EBP 0x810xc50x??0x000x000x000x550xc2",
          "ESI 0x830xc60x??0x560xc3",        #add esi + push + ret
          "ESI 0x810xc60x??0x000x000x000x560xc3",
          "ESI 0x830xc60x??0x560xc2",		 #add esi + push + ret n
          "ESI 0x810xc60x??0x000x000x000x560xc3",
          "EDI 0x830xc70x??0x570xc3",        #add edi + push + ret
          "EDI 0x810xc70x??0x000x000x000x570xc3",
          "EDI 0x830xc70x??0x570xc2",		 #add edi + push + ret n
          "EDI 0x810xc70x??0x000x000x000x570xc3"
          ]

          posvalop=[
          "EAX 0x830xe8x??0x500xc3",        #sub eax -value + push + ret
          "EAX 0x810xe8x??0xff0xff0xff0x500xc3",
          "EAX 0x830xe8x??0x500xc2",		 #
          "EAX 0x810xe8x??0xff0xff0xff0x500xc2",
          "ECX 0x830xe90x??0x510xc3",        #sub ecx -value + push + ret
          "ECX 0x810xe90x??0xff0xff0xff0x510xc3",
          "ECX 0x830xe90x??0x510xc2",
          "ECX 0x810xe90x??0xff0xff0xff0x510xc2",
          "EDX 0x830xea0x??0x520xc3",        #sub edx -value + push + ret
          "EDX 0x810xea0x??0xff0xff0xff0x520xc3",
          "EDX 0x830xea0x??0x520xc2",
          "EDX 0x810xea0x??0xff0xff0xff0x520xc3",
          "EBX 0x830xeb0x??0x530xc3",        #sub ebx -value + push + ret
          "EBX 0x810xeb0x??0xff0xff0xff0x530xc3",
          "EBX 0x830xeb0x??0x530xc2",
          "EBX 0x810xeb0x??0xff0xff0xff0x530xc3",
          "ESP 0x830xec0x??0x540xc3",        #sub esp -value + push + ret
          "ESP 0x810xec0x??0xff0xff0xff0x540xc3",
          "ESP 0x830xec0x??0x540xc2",
          "ESP 0x810xec0x??0xff0xff0xff0x540xc2",
          "EBP 0x830xed0x??0x550xc3",        #sub ebp -value + push + ret
          "EBP 0x810xed0x??0xff0xff0xff0x550xc3",
          "EBP 0x830xed0x??0x550xc2",
          "EBP 0x810xed0x??0xff0xff0xff0x550xc2",
          "ESI 0x830xee0x??0x560xc3",        #sub esi -value + push + ret
          "ESI 0x810xee0x??0xff0xff0xff0x560xc3",
          "ESI 0x830xee0x??0x560xc2",
          "ESI 0x810xee0x??0xff0xff0xff0x560xc3",
          "EDI 0x830xef0x??0x570xc3",        #sub edi -value + push + ret
          "EDI 0x810xef0x??0xff0xff0xff0x570xc3",
          "EDI 0x830xef0x??0x570xc2",
          "EDI 0x810xef0x??0xff0xff0xff0x570xc3"
          ]

          negop=[
          "EAX 0x810xe80x??0x000x000x000x500xc3", #sub eax + push + ret
          "EAX 0x810xe80x??0x000x000x000x500xc2",
          "EAX 0x830xe80x??0x500xc3",
          "EAX 0x830xe80x??0x500xc2",
          "ECX 0x810xe90x??0x000x000x000x510xc3", #sub ecx + push + ret
          "ECX 0x810xe90x??0x000x000x000x510xc2",
          "ECX 0x830xe90x??0x510xc3",
          "ECX 0x830xe90x??0x510xc2",
          "EDX 0x810xea0x??0x000x000x000x520xc3", #sub edx + push + ret
          "EDX 0x810xea0x??0x000x000x000x520xc2",
          "EDX 0x830xea0x??0x520xc3",
          "EDX 0x830xea0x??0x520xc2",
          "EBX 0x810xeb0x??0x000x000x000x530xc3", #sub ebx + push + ret
          "EBX 0x810xeb0x??0x000x000x000x530xc2",
          "EBX 0x830xeb0x??0x530xc3",
          "EBX 0x830xeb0x??0x530xc2",
          "ESP 0x810xec0x??0x000x000x000x540xc3", #sub esp + push + ret
          "ESP 0x810xec0x??0x000x000x000x540xc2",
          "ESP 0x830xec0x??0x540xc3",
          "ESP 0x830xec0x??0x540xc2",
          "EBP 0x810xed0x??0x000x000x000x550xc3", #sub ebp + push + ret
          "EBP 0x810xed0x??0x000x000x000x550xc2",
          "EBP 0x830xed0x??0x550xc3",
          "EBP 0x830xed0x??0x550xc2",
          "ESI 0x810xee0x??0x000x000x000x560xc3", #sub esi + push + ret
          "ESI 0x810xee0x??0x000x000x000x560xc2",
          "ESI 0x830xee0x??0x560xc3",
          "ESI 0x830xee0x??0x560xc2",
          "EDI 0x810xef0x??0x000x000x000x570xc3", #sub edi + push + ret
          "EDI 0x810xef0x??0x000x000x000x570xc2",
          "EDI 0x830xef0x??0x570xc3",
          "EDI 0x830xef0x??0x570xc2"
          ]

          negvalop=[
          "EAX 0x810xc00x??0xFF0xFF0xFF0x500xc3",  #add eax - x + push + ret
          "EAX 0x830xc00x??0x500xc3",
          "EAX 0x810xc00x??0xFF0xFF0xFF0x500xc2",  #add eax - x + push + ret n
          "EAX 0x830xc00x??0x500xc2",
          "ECX 0x810xc10x??0xFF0xFF0xFF0x510xc3",  #add ecx - x + push + ret
          "ECX 0x830xc10x??0x510xc3",
          "ECX 0x810xc10x??0xFF0xFF0xFF0x510xc2",  #add ecx - x + push + ret n
          "ECX 0x830xc10x??0x510xc2",
          "EDX 0x810xc20x??0xFF0xFF0xFF0x520xc3",  #add edx - x + push + ret
          "EDX 0x830xc20x??0x520xc3",
          "EDX 0x810xc20x??0xFF0xFF0xFF0x520xc2",  #add edx - x + push + ret n
          "EDX 0x830xc20x??0x520xc2",
          "EBX 0x810xc30x??0xFF0xFF0xFF0x530xc3",  #add ebx - x + push + ret
          "EBX 0x830xc30x??0x530xc3",
          "EBX 0x810xc30x??0xFF0xFF0xFF0x530xc2",  #add ebx - x + push + ret n
          "EBX 0x830xc30x??0x530xc2",
          "ESP 0x810xc40x??0xFF0xFF0xFF0x540xc3",  #add esp - x + push + ret
          "ESP 0x830xc40x??0x540xc3",
          "ESP 0x810xc40x??0xFF0xFF0xFF0x540xc2",  #add esp - x + push + ret n
          "ESP 0x830xc40x??0x540xc2",
          "EBP 0x810xc50x??0xFF0xFF0xFF0x550xc3",  #add ebp - x + push + ret
          "EBP 0x830xc50x??0x550xc3",
          "EBP 0x810xc50x??0xFF0xFF0xFF0x550xc2",  #add ebp - x + push + ret n
          "EBP 0x830xc50x??0x550xc2",
          "ESI 0x810xc60x??0xFF0xFF0xFF0x560xc3",  #add esi - x + push + ret
          "ESI 0x830xc60x??0x560xc3",
          "ESI 0x810xc60x??0xFF0xFF0xFF0x560xc2",  #add esi - x + push + ret n
          "ESI 0x830xc60x??0x560xc2",
          "EDI 0x810xc70x??0xFF0xFF0xFF0x570xc3",  #add edi - x + push + ret
          "EDI 0x830xc70x??0x570xc3",
          "EDI 0x810xc70x??0xFF0xFF0xFF0x570xc2",  #add edi - x + push + ret n
          "EDI 0x830xc70x??0x570xc2",
          ]

          offsettable=imm.createTable('pvefindaddr Jump to '+targetreg+'+offset results',['Address','Offset','Instruction','Module','Access'])
          startoffset=minoffset
          if startoffset > maxoffset:
              tmpoffset=startoffset
              startoffset=maxoffset
              maxoffset=tmpoffset
          if startoffset < -254:
              startoffset=-254
          if maxoffset > 254:
              maxoffset=254
          imm.log("Target register : %s " % targetreg)
          imm.log("Offset range : from %d to %d" % (startoffset,maxoffset))
          if modulefilter <> "":
            imm.log("Only show addresses from module %s " % modulefilter)
          imm.log("-----------------------------------------------------")
          startoff=startoffset
          ofstring=""
          while startoff <= maxoffset:
            if startoff < 0:
                ofstring=tohexbyte(255+startoff+1)
            if startoff > 0:
                ofstring=tohexbyte(startoff)
            if startoff != 0:
               imm.log("Finding pointers to jump to %s offset %s" % (targetreg,startoff))
               imm.updateLog()
               for thiscall in allop:
                  imm.updateLog()
                  if thiscall.find(targetreg) > -1:
                    thiscall=thiscall.replace(targetreg+" ","")
                    newsearch=thiscall.replace("??",ofstring).replace("0x","\\x")
                    #perform search
                    addys=imm.search( newsearch.decode('string_escape'))
                    imm.log("%d pointers found" % len(addys))
                    for ad1 in addys:
                        module = getmodnamefromptr(ad1)
                        if not module:
                          module = "none"
                        else:
                          if module=="":
                             module = "none"
                          else:
                             module = module.lower()
                        if getmoduleprop(module,"fixup")=="0":
                          if (modulefilter=="") or (modulefilter <> "" and module.upper().find(modulefilter.upper()) > -1):
                            if (noos==0) or (noos==1 and isosmodule(module)==0):
                             aspec=addressspec(tohex(ad1)).upper()
                             if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                               page   = imm.getMemoryPagebyAddress( ad1 )
                               access = page.getAccess( human = True )
                               hexaddr=tohex(ad1)
                               op = imm.Disasm( ad1 )
                               opstring=op.getDisasm()
                               offsettable.add(0,["%s"%(tohex(ad1)),"%d"%(startoff),"%s"%(opstring),"%s"%(module),"%s"%(access)])
                               imm.updateLog()
                               tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                               nrfound=nrfound+1
               if startoff > 0:
                    for addcall in posop:
                        if addcall.find(targetreg) > -1:
                            addcall=addcall.replace(targetreg+" ","")
                            newsearch=addcall.replace("??",ofstring).replace("0x","\\x")
                            addys=imm.search( newsearch.decode('string_escape'))
                            for ad1 in addys:
                                module = getmodnamefromptr(ad1)
                                if not module:
                                   module = "none"
                                else:
                                   if module=="":
                                      module = "none"
                                   else:
                                      module = module.lower()
                                if getmoduleprop(module,"fixup")=="0":
                                 if (modulefilter=="") or (modulefilter != "" and module.upper().find(modulefilter.upper()) > -1):
                                  if (noos==0) or (noos==1 and isosmodule(module)==0):
                                    aspec=addressspec(tohex(ad1)).upper()
                                    if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                                      page   = imm.getMemoryPagebyAddress( ad1 )
                                      access = page.getAccess( human = True )
                                      hexaddr=tohex(ad1)
                                      op = imm.Disasm( ad1 )
                                      opstring=op.getDisasm()
                                      offsettable.add(0,["%s"%(tohex(ad1)),"%d"%(startoff),"%s"%(opstring),"%s"%(module),"%s"%(access)])
                                      imm.updateLog()
                                      tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                                      nrfound=nrfound+1
                    for addcall in posvalop:
                        if addcall.find(targetreg) > -1:
                            addcall=addcall.replace(targetreg+" ","")
                            newsearch=addcall.replace("??",tohexbyte(255+startoff+1)).replace("0x","\\x")
                            addys=imm.search( newsearch.decode('string_escape'))
                            for ad1 in addys:
                                module = getmodnamefromptr(ad1)
                                if not module:
                                   module = "none"
                                else:
                                   if module=="":
                                      module = "none"
                                   else:
                                      module = module.lower()
                                if getmoduleprop(module,"fixup")=="0":
                                 if (modulefilter=="") or (modulefilter != "" and module.upper().find(modulefilter.upper()) > -1):
                                  if (noos==0) or (noos==1 and isosmodule(module)==0):
                                    aspec=addressspec(tohex(ad1)).upper()
                                    if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                                      page   = imm.getMemoryPagebyAddress( ad1 )
                                      access = page.getAccess( human = True )
                                      hexaddr=tohex(ad1)
                                      op = imm.Disasm( ad1 )
                                      opstring=op.getDisasm()
                                      offsettable.add(0,["%s"%(tohex(ad1)),"%d"%(startoff),"%s"%(opstring),"%s"%(module),"%s"%(access)])
                                      imm.updateLog()
                                      tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                                      nrfound=nrfound+1
               if startoff < 0:
                    for subcall in negop:
                        if subcall.find(targetreg) > -1:
                            subcall=subcall.replace(targetreg+" ","")
                            newsearch=subcall.replace("??",tohexbyte(startoff*(-1))).replace("0x","\\x")
                            addys=imm.search( newsearch.decode('string_escape'))
                            for ad1 in addys:
                                module = getmodnamefromptr(ad1)
                                if not module:
                                   module = "none"
                                else:
                                   if module=="":
                                      module = "none"
                                   else:
                                      module = module.lower()
                                if getmoduleprop(module,"fixup")=="0":
                                 if (modulefilter=="") or (modulefilter != "" and module.upper().find(modulefilter.upper()) > -1):
                                  if (noos==0) or (noos==1 and isosmodule(module)==0):
                                    aspec=addressspec(tohex(ad1)).upper()
                                    if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                                      page   = imm.getMemoryPagebyAddress( ad1 )
                                      access = page.getAccess( human = True )
                                      hexaddr=tohex(ad1)
                                      op = imm.Disasm( ad1 )
                                      opstring=op.getDisasm()
                                      offsettable.add(0,["%s"%(tohex(ad1)),"%d"%(startoff),"%s"%(opstring),"%s"%(module),"%s"%(access)])
                                      imm.updateLog()
                                      tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                                      nrfound=nrfound+1
                    for subcall in negvalop:
                        if subcall.find(targetreg) > -1:
                            subcall=subcall.replace(targetreg+" ","")
                            newsearch=subcall.replace("??",tohexbyte(255+startoff+1).replace("0x","\\x"))
                            addys=imm.search( newsearch.decode('string_escape'))
                            for ad1 in addys:
                                module = getmodnamefromptr(ad1)
                                if not module:
                                   module = "none"
                                else:
                                   if module=="":
                                      module = "none"
                                   else:
                                      module = module.lower()
                                if getmoduleprop(module,"fixup")=="0":
                                 if (modulefilter=="") or (modulefilter != "" and module.upper().find(modulefilter.upper()) > -1):
                                  if (noos==0) or (noos==1 and isosmodule(module)==0):
                                    aspec=addressspec(tohex(ad1)).upper()
                                    if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                                      page   = imm.getMemoryPagebyAddress( ad1 )
                                      access = page.getAccess( human = True )
                                      hexaddr=tohex(ad1)
                                      op = imm.Disasm( ad1 )
                                      opstring=op.getDisasm()
                                      offsettable.add(0,["%s"%(tohex(ad1)),"%d"%(startoff),"%s"%(opstring),"%s"%(module),"%s"%(access)])
                                      imm.updateLog()
                                      tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                                      nrfound=nrfound+1
            startoff=startoff+1
          imm.log("Output written to "+filename)
          if nrfound>0:
            imm.log("Found %d address(es)" % nrfound)
            return "Found %d address(es) (Check the Log Window/Table for details)" % nrfound
          else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
          imm.log("--------------------------------------------------------------")

        else:
          usage(imm)
          return "Error: Please provide register, offset (start and end int) and optional module name"



    if args[0] == "depxp" or args[0]=="depxpsp3":
          imm.log("--------------------------------------------------------------------------------")
          imm.log("Search for addresses used to disable DEP (-> XP SP3) via NtSetInformationProcess")
          imm.log("--------------------------------------------------------------------------------")
          opcodej=["\xb0\x01\xc3", #mov al,0x1 / ret
                   "\xb0\x01\xc2\x04", #mov al,0x1 / ret 04
                   "\xb0\x01\xc2\x08", #mov al,0x1 / ret 08
                   "\x31\xc0\x40\xc3", #xor eax,eax/inc eax/ret
                   "\x31\xc0\x40\xc2\x04", #xor eax,eax/inc eax/ret 04
                   "\x31\xc0\x40\xc2\x08", #xor eax,eax/inc eax/ret 08
                   "\x31\xc0\x40\xc2\x1c"] #xor eax,eax/inc eax/ret 1c
          imm.log("Phase 1 : set eax to 1 and return")
          imm.log("--------------------------------")
          filename="depxp.txt"
          resetfile(filename)
          writemodinfo(filename)
          for opjc in opcodej:
                addys=imm.search( opjc )
                results += addys
                for ad1 in addys:
                  module = getmodnamefromptr(ad1)
                  if not module:
                     module = "none"
                  else:
                     if module=="":
                        module = "none"
                     else:
                        module = module.lower()
                  page   = imm.getMemoryPagebyAddress( ad1 )
                  access = page.getAccess( human = True )
                  op = imm.Disasm( ad1 )
                  opstring=op.getDisasm()
                  imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, ad1, module,access), address = ad1)
                  tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                  nrfound+=1
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          nrfound=0
          mod = imm.getModule("ntdll.dll")
          imm.log("Phase 2 : compare AL with 1, push 0x2 and pop esi")
          imm.log("-------------------------------------------------")
          searchfor="\x3c\x01\x6a\x02\x5e";
          ret = imm.search( searchfor )
          for res in ret:
              module = getmodnamefromptr(res)
              if not module:
                module = "none"
              else:
                if module=="":
                    module = "none"
                else:
                    module = module.lower()
              page   = imm.getMemoryPagebyAddress( res )
              access = page.getAccess( human = True )
              op = imm.Disasm( res )
              opstring=op.getDisasm()
              imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, res, module,access), address = res)
              tofile("Found "+opstring+" at 0x" + tohex(res)+" ["+module+"]",filename,ad1)
              nrfound+=1
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          nrfound=0
          imm.log("Finding addresses for EBP stack adjustment")
          imm.log("------------------------------------------")
          searchebp=["\x8b\xec\xc3", #mov ebp,esp / ret
                     "\x8b\xec\xc2\x04\x00",  #mov ebp,esp / ret 4
                     "\x54\x5d\xc3", #push ebp / pop ebp / ret
                     "\x54\x5d\xc2\x04\x00"]   #push ebp / pop ebp / ret 4
          for sebp in searchebp:
              thisadr=imm.search(sebp)
              results += thisadr
              for ad1 in thisadr:
                  module = getmodnamefromptr(ad1)
                  if not module:
                    module = "none"
                  else:
                    if module=="":
                        module = "none"
                    else:
                        module = module.lower()
                  page   = imm.getMemoryPagebyAddress( ad1 )
                  access = page.getAccess( human = True )
                  op = imm.Disasm( ad1 )
                  opstring=op.getDisasm()
                  imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, ad1, module,access), address = ad1)
                  tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                  nrfound=nrfound+1
          imm.log("Output written to "+filename)
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          return "Done - check %s" % filename

    if args[0] == "depwin2k3":
          filename="depwin2k3"
          resetfile(filename)
          writemodinfo(filename)
          imm.log("-----------------------------------------------------------------------------------------------")
          imm.log("Search for addresses used to disable DEP (Windows 2003 SP2 and SP3) via NtSetInformationProcess")
          imm.log("-----------------------------------------------------------------------------------------------")
          opcodej=["\xb0\x01\xc3", #mov al,0x1 / ret
                   "\xb0\x01\xc2\x04", #mov al,0x1 / ret 04
                   "\xb0\x01\xc2\x08", #mov al,0x1 / ret 08
                   "\x31\xc0\x40\xc3", #xor eax,eax/inc eax/ret
                   "\x31\xc0\x40\xc2\x04", #xor eax,eax/inc eax/ret 04
                   "\x31\xc0\x40\xc2\x08", #xor eax,eax/inc eax/ret 08
                   "\x31\xc0\x40\xc2\x1c"] #xor eax,eax/inc eax/ret 1c
          imm.log("Phase 1 : set eax to 1 and return")
          imm.log("--------------------------------")
          for opjc in opcodej:
                addys=imm.search( opjc )
                results += addys
                for ad1 in addys:
                  module = imm.findModule(ad1)
                  if not module:
                      module = "none"
                  else:
                      module = module[0].lower()
                  page   = imm.getMemoryPagebyAddress( ad1 )
                  access = page.getAccess( human = True )
                  op = imm.Disasm( ad1 )
                  opstring=op.getDisasm()
                  imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, ad1, module,access), address = ad1)
                  tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                  nrfound+=1
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          nrfound=0
          mod = imm.getModule("ntdll.dll")
          imm.log("Phase 2 : Initiate NX Disable process")
          imm.log("-------------------------------------------------")
          searchfor="\x83\x7d\xfc\x00";
          ret = imm.search( searchfor )
          for res in ret:
              module = imm.findModule(res)
              if not module:
                module="none"
              else:
                module=module[0].lower()
              page   = imm.getMemoryPagebyAddress( res )
              access = page.getAccess( human = True )
              op = imm.Disasm( res )
              opstring=op.getDisasm()
              imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, res, module,access), address = res)
              tofile("Found "+opstring+" at 0x" + tohex(res)+" ["+module+"]",filename,ad1)
              nrfound+=1
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          nrfound=0
          imm.log("Finding addresses for EBP stack adjustment")
          imm.log("------------------------------------------")
          searchebp=["\x8b\xec\xc3", #mov ebp,esp / ret
                     "\x8b\xec\xc2\x04\x00",  #mov ebp,esp / ret 4
                     "\x54\x5d\xc3", #push esp / pop ebp / ret
                     "\x54\x5d\xc2\x04\x00"]   #push esp / pop ebp / ret 4
          for sebp in searchebp:
              thisadr=imm.search(sebp)
              results += thisadr
              for ad1 in thisadr:
                  module = imm.findModule(ad1)
                  if not module:
                      module = "none"
                  else:
                      module = module[0].lower()
                  page   = imm.getMemoryPagebyAddress( ad1 )
                  access = page.getAccess( human = True )
                  op = imm.Disasm( ad1 )
                  opstring=op.getDisasm()
                  imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, ad1, module,access), address = ad1)
                  tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                  nrfound+=1
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          nrfound=0
          imm.log("Finding addresses for ESI stack adjustment")
          imm.log("------------------------------------------")
          searchebp=["\x8b\xf4\xc3", #mov esi,esp / ret
                     "\x8b\xf4\xc2\x04\x00",  #mov esi,esp / ret 4
                     "\x54\x5e\xc3", #push esp / pop esi / ret
                     "\x54\x5e\xc2\x04\x00",   #push esp / pop esi / ret 4
                     "\x55\x5e\xc3", #push ebp / pop esi / ret # only use this one if you have pushed ESP to EBP first
                     "\x55\x5e\xc2\x04\x00"]   #push ebp / pop esi / ret 4 # only use this one if you have pushed ESP to EBP first
          for sebp in searchebp:
              thisadr=imm.search(sebp)
              results += thisadr
              for ad1 in thisadr:
                  module = imm.findModule(ad1)
                  if not module:
                      module = "none"
                  else:
                      module = module[0].lower()
                  page   = imm.getMemoryPagebyAddress( ad1 )
                  access = page.getAccess( human = True )
                  op = imm.Disasm( ad1 )
                  opstring=op.getDisasm()
                  imm.log("Found %s at 0x%08x (%s) - Access: (%s)" % (opstring, ad1, module,access), address = ad1)
                  tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module+"]",filename,ad1)
                  nrfound+=1
          if results:
            imm.log("Found %d address(es)" % nrfound)
          else:
            imm.log("No addresses found")
          imm.log("Output written to "+filename)
          return "Done - check %s" % filename


    if args[0] == "jseh":
          filename="jseh.txt"
          resetfile(filename)
          writemodinfo(filename)
          showred=0
          showall=0
          if len(args) > 1:
              if args[1].lower()== "all":
			     showall=1
          imm.log("-----------------------------------------------------------------------")
          imm.log("Search for jmp/call dword[ebp/esp+nn] (and other) combinations started ")
          imm.log("-----------------------------------------------------------------------")
          opcodej=["\xff\x54\x24\x08", #call dword ptr [esp+08]
                   "\xff\x64\x24\x08", #jmp dword ptr [esp+08]
                   "\xff\x54\x24\x14", #call dword ptr [esp+14]
                   "\xff\x54\x24\x14", #jmp dword ptr [esp+14]
                   "\xff\x54\x24\x1c", #call dword ptr [esp+1c]
                   "\xff\x54\x24\x1c", #jmp dword ptr [esp+1c]
                   "\xff\x54\x24\x2c", #call dword ptr [esp+2c]
                   "\xff\x54\x24\x2c", #jmp dword ptr [esp+2c]
                   "\xff\x54\x24\x44", #call dword ptr [esp+44]
                   "\xff\x54\x24\x44", #jmp dword ptr [esp+44]
                   "\xff\x54\x24\x50", #call dword ptr [esp+50]
                   "\xff\x54\x24\x50", #jmp dword ptr [esp+50]
                   "\xff\x55\x0c",     #call dword ptr [ebp+0c]
                   "\xff\x65\x0c",     #jmp dword ptr [ebp+0c]
                   "\xff\x55\x24",     #call dword ptr [ebp+24]
                   "\xff\x65\x24",     #jmp dword ptr [ebp+24]
                   "\xff\x55\x30",     #call dword ptr [ebp+30]
                   "\xff\x65\x30",     #jmp dword ptr [ebp+30]
                   "\xff\x55\xfc",     #call dword ptr [ebp-04]
                   "\xff\x65\xfc",     #jmp dword ptr [ebp-04]
                   "\xff\x55\xf4",     #call dword ptr [ebp-0c]
                   "\xff\x65\xf4",     #jmp dword ptr [ebp-0c]
                   "\xff\x55\xe8",     #call dword ptr [ebp-18]
                   "\xff\x65\xe8",     #jmp dword ptr [ebp-18]
				   "\x83\xc4\x08\xc3", #add esp,8 + ret
                   "\x83\xc4\x08\xc2"] #add esp,8 + ret X
          for opjc in opcodej:
                addys=imm.search( opjc )
                results += addys
                for ad1 in addys:
                  module = imm.findModule(ad1)
                  if not module:
                    module=""
                    page   = imm.getMemoryPagebyAddress( ad1 )
                    access = page.getAccess( human = True )
                    op = imm.Disasm( ad1 )
                    opstring=op.getDisasm()
                    imm.log("Found %s at 0x%08x - Access: (%s)" % (opstring, ad1, access), address = ad1,highlight=1)
                    tofile("Found "+opstring+" at 0x" + tohex(ad1)+" [none]",filename,ad1)
                    nrfound+=1
                  else:
                    if showall==1:
                          page   = imm.getMemoryPagebyAddress( ad1 )
                          access = page.getAccess( human = True )
                          op = imm.Disasm( ad1 )
                          opstring=op.getDisasm()
                          if ismodulenosafeseh(module[0])==1:
                               extratext="=== Safeseh : NO ==="
                               showred=1
                          else:
                               extratext="Safeseh protected"
                               showred=0
                          imm.log("Found %s at 0x%08x (%s) - Access: (%s) - %s" % (opstring, ad1, module,access,extratext), address = ad1,highlight=showred)
                          tofile("Found "+opstring+" at 0x" + tohex(ad1)+" ["+module[0]+"] - " + extratext,filename,ad1)
                          nrfound+=1
          imm.log("Search complete")
          imm.log("Output written to "+filename)
          if results:
            imm.log("Found %d address(es)" % nrfound)
            return "Found %d address(es) (Check the Log Windows for details)" % nrfound
          else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
          imm.log("--------------------------------------------------------------")
          return "Done - check %s" % filename


    if args[0] == "fa":
          filename="fa.txt"
          resetfile(filename)
          writemodinfo(filename)
          nrfound=0
          nrfoundptr=0
          opcodej=["\x41\x41\x41\x41"]
          if len(args) == 3:
              stra=binascii.a2b_hex(args[1]+args[2])
              opcodej=[stra]
              imm.log("Custom provided search pattern found (2 bytes)")
          if len(args) == 5:
              strb=binascii.a2b_hex(args[1]+args[2]+args[3]+args[4])
              opcodej=[strb]
              imm.log("Custom provided search pattern found (4 bytes)")
          imm.log("---------------------------------------------------------------------------")
          imm.log("Search for locations that contain the search pattern %s" % opcodej[0])
          imm.log("---------------------------------------------------------------------------")
          for opjc in opcodej:
                imm.log("Searching for %s " % opjc)
                addys=imm.search( opjc )
                results += addys
          for all in results:
                nrfound += 1
          if results:
            imm.log("Found %d location(s) that point to the search string" % (nrfound))
            imm.log("Now searching for pointers to those location(s)...")
            for pntr in results:
                 #first reverse the address so we can use it in a search operation
                 taddr=tohex(pntr)
                 sstr=taddr[6]+taddr[7]+" "+taddr[4]+taddr[5]+" "+taddr[2]+taddr[3]+" "+taddr[0]+taddr[1]
                 imm.log("  -> searching for %s" % (sstr), address=pntr)
                 addys=imm.search( sstr )
                 for adptr in addys:
                    imm.log(" ** Found pointer at 0x%08x ** " % (adptr), address = adptr)
                    tofile("Found pointer to "+tohex(pntr)+" at " + tohex(adptr),filename,adptr)
                    nrfoundptr += 1
                 sstr=taddr[4]+taddr[5]+" "+taddr[2]+taddr[3]+" "+taddr[0]+taddr[1]
                 imm.log("  -> searching for %s (possible close pointer)" % sstr)
                 addus=imm.search( sstr )
                 for adptr in addys:
                     imm.log(" ** Possible close pointer found at 0x%08x ** " % (adptr), address = adptr)
                     tofile("Found possible close pointer to "+tohex(pntr)+" at "+tohex(adptr),filename,adptr)
                     nrfoundptr += 1
            if nrfoundptr > 0:
			   imm.log("Pointers to pointers found : %d !" % nrfoundptr)
            else:
			   imm.log("Sorry, no pointers to pointers found !")
          else:
            imm.log("No addresses found")
            return "Sorry, no addresses found"
          imm.log("--------------------------------------------------------------")
          return "Done - check %s" % filename

    if args[0] == "pattern_create":
      imm.log("-------------------------------------------------------------------------")
      imm.log("Creating (Metasploit) pattern...");
      imm.log("-------------------------------------------------------------------------")
      if len(args) != 2:
        imm.log("Syntax : !pvefindaddr pattern_create size")
        return "Invalid syntax"
      else:
        mypat=pattern_create(args[1])
        imm.log("Pattern of %s bytes :" % args[1])
        imm.log(mypat)
        filename="mspattern.txt"
        resetfile(filename)
        FILE=open(filename,"a")
        FILE.write("Cyclic pattern of " + args[1]+" characters :\n")
        FILE.write(mypat)
        FILE.close()
        return "Done - check %s" % filename

    if args[0] == "pattern_offset":
      imm.log("-------------------------------------------------------------------------")
      imm.log("Calculating offset in (Metasploit) pattern...");
      imm.log("-------------------------------------------------------------------------")
      if (len(args) != 2 and len(args) != 3):
        imm.log("Syntax : !pvefindaddr pattern_offset Pattern [Size]")
      else:
        if len(args)==2:
            pattern_offset(args[1],8000,imm)
        if len(args)==3:
            pattern_offset(args[1],args[2],imm)




    if args[0] == "findmsp" or args[0] == "suggest":
      imm.log("-------------------------------------------------------------------------")
      imm.log("Searching for metasploit pattern references")
      imm.log("-------------------------------------------------------------------------")
      mspattern=pattern_create(20280)
      regs = imm.getRegs()
      if len(args) == 1:
        fchars=pattern_create(8)
        imm.log("[1] Searching for first 8 characters of Metasploit pattern : %s" % fchars)
        imm.log("=====================================================================")
        imm.updateLog()
        firstchars=""
        for mspchar in fchars:
            firstchars += hex(ord(mspchar)).replace("0x"," ")
        toSearch = firstchars.replace(" ",'\\x').decode('string_escape')
        toSearch = toSearch.decode('string_escape')
        sresults=imm.search( toSearch )
        if (len(sresults) == 0):
            imm.log(" ** Could not find begin of Metasploit pattern (ascii) in memory ! **")
        else:
            for sr in sresults:
                imm.log(" - Found begin of Metasploit pattern at 0x%08x" % sr,address=sr)
        imm.log("")
        #perhaps it's unicode
        firstchars=""
        for mspchar in fchars:
            firstchars += hex(ord(mspchar)).replace("0x"," ")+"\x00"
        toSearch = firstchars.replace(" ",'\\x').decode('string_escape')
        toSearch = toSearch.decode('string_escape')
        sresults=imm.search( toSearch )
        if (len(sresults) == 0):
            imm.log(" ** Could not find begin of Metasploit pattern (unicode expanded) in memory ! **")
        else:
            for sr in sresults:
                imm.log(" - Found begin of Unicode expanded Metasploit pattern at 0x%08x" % sr,address=sr)
        imm.log("")
        imm.updateLog()
        imm.log("[2] Checking register addresses and contents")
        imm.log("============================================")
        for reg in regs:
           imm.updateLog()
           foundreg=0
           regvalue = tohex(regs[reg])
           hex1=regvalue[6]+regvalue[7]
           hex2=regvalue[4]+regvalue[5]
           hex3=regvalue[2]+regvalue[3]
           hex4=regvalue[0]+regvalue[1]
           asciivalue=toascii(imm,hex1)+toascii(imm,hex2)+toascii(imm,hex3)+toascii(imm,hex4)
		   #see if string can be found in Metasploit pattern
           if asciivalue in mspattern:
              PatternPos = mspattern.find(asciivalue)
              imm.log(" - Register %s is overwritten with Metasploit pattern at position %d" % (reg,PatternPos))
              foundreg=1
              if reg == 'EIP':
                 g_typeofsploit=1
                 g_offset=PatternPos
           if asciivalue in mspattern.lower():
              PatternPos = mspattern.lower().find(asciivalue)
              imm.log(" - Register %s is overwritten with lowercase Metasploit pattern at position %d" % (reg,PatternPos))
              foundreg=1
              if reg == 'EIP':
                 g_typeofsploit=1
                 g_offset=PatternPos
           if asciivalue in mspattern.upper():
              PatternPos = mspattern.upper().find(asciivalue)
              imm.log(" - Register %s is overwritten with uppercase Metasploit pattern at position %d" % (reg,PatternPos))
              foundreg=1
              if reg == 'EIP':
                 g_typeofsploit=1
                 g_offset=PatternPos
           #perhaps it's a unicode pattern.
           if hex4=="00" and hex2=="00":
            if reg == 'EIP':
		      #get contents at ESP
              espaddress=regs["ESP"]
              regesp=imm.readMemory(espaddress,4)
              ascuni=regesp[0] + regesp[2] + toascii(imm,hex1) + toascii(imm,hex3)
              imm.log(" - EIP overwritten with unicode pattern '%s%s%s%s'. Together with contents of ESP (0x%s) this makes %s" % (hex4,hex3,hex2,hex1,tohex(espaddress),ascuni))
              if ascuni in mspattern:
                  PatternPos = mspattern.find(ascuni)
                  imm.log("    It looks like EIP was overwritten with Metasploit pattern at position %d" % PatternPos)
                  g_typeofsploit=1
                  g_offset=PatternPos
            else:
              if hex1<>"00" and hex3<>"00":
                imm.log(" - %s overwritten with unicode pattern '%s%s%s%s'." % (reg,hex4,hex3,hex2,hex1))
           #perhaps we forgot to use Metasploit pattern - look for 41414141/42424242
           if (asciivalue=="AAAA" or asciivalue=="BBBB"):
               imm.log(" - Register %s is overwritten with %s - Try using a Metasploit pattern next time" % (reg,asciivalue))
               if reg == 'EIP':
                 guessstart(asciivalue,1)
           if (asciivalue=="aaaa" or asciivalue=="bbbb"):
               imm.log(" - Register %s is overwritten with %s (lowercase)- Try using a Metasploit pattern next time" % (reg,asciivalue))
               if reg == 'EIP':
                 guessstart(asciivalue,1)
           if (hex1=="00" and hex2=="41" and hex3=="00" and hex4=="41"):
               imm.log(" - Register %s is overwritten with 00410041 (Unicode ?) - Try using a Metasploit pattern next time" % (reg))
           #now look at contents of register
           regcnt=0
           offfound=0
           imm.updateLog()
           while (regcnt < 127 and offfound==0):
            try:
               thisregaddr=regs[reg]+regcnt
               if regcnt > 0:
                  regofftxt="+" + hex(regcnt)
               else:
                  regofftxt=""
               cont  = imm.readMemory(thisregaddr, 4 )
               if cont == "":
                  cont="REALLYBADCOFFEE"
               if cont in mspattern:
                  PatternPos = mspattern.find(cont)
                  if PatternPos >= 0:
                    imm.log(" - Register %s points to Metasploit pattern at position %d" % (reg+regofftxt,PatternPos))
                    offfound=1
                    if (PatternPos < g_regpos) or (g_regpos == 0):
                       g_jumpreg=reg
                       g_regoff=regofftxt
                       g_regpos=PatternPos
               if cont in mspattern.lower():
                  PatternPos = mspattern.lower().find(cont)
                  if PatternPos >= 0:
                    imm.log(" - Register %s points to lowercase Metasploit pattern at position %d" % (reg+regofftxt,PatternPos))
                    offfound=1
                    if (PatternPos < g_regpos) or (g_regpos == 0):
                       g_jumpreg=reg
                       g_regoff=regofftxt
                       g_regpos=PatternPos
               if cont in mspattern.upper():
                  PatternPos = mspattern.upper().find(cont)
                  if PatternPos >= 0:
                    imm.log(" - Register %s points to uppercase Metasploit pattern at position %d" % (reg+regofftxt,PatternPos))
                    offfound=1
                    if (PatternPos < g_regpos) or (g_regpos == 0):
                       g_jumpreg=reg
                       g_regoff=regofftxt
                       g_regpos=PatternPos
               if (cont=="AAAA" or cont=="BBBB"):
                  imm.log(" - Register %s points to %s - Try using a Metasploit pattern next time" % (reg+regofftxt,cont))
                  offfound=1
               if (cont=="aaaa" or cont=="bbbb"):
                  imm.log(" - Register %s points to %s (converted to lowercase ?)- Try using a Metasploit pattern next time" % (reg+regofftxt,cont))
                  offfound=1
               uregvalue=imm.readMemory(thisregaddr,8)
               ascuni=uregvalue[0] + uregvalue[2] + uregvalue[4] + uregvalue[6]
               if ascuni in mspattern:
                    offfound=1
                    PatternPos = mspattern.find(ascuni)
                    imm.log(" - Register %s points to position %d in Metasploit pattern (unicode expanded)" % (reg,PatternPos))
            except:
               pass
            regcnt=regcnt+1
            imm.updateLog()
	    #finally look at sehchain
        imm.log("")
        imm.log("[3] Checking seh chain")
        imm.log("======================")
        imm.updateLog()
        thissehchain=imm.getSehChain()
        nrofentries=0
        for chainentry in thissehchain:
            #try:
               imm.updateLog()
               sehvalue=tohex(chainentry[1])
               hex1=sehvalue[6]+sehvalue[7]
               hex2=sehvalue[4]+sehvalue[5]
               hex3=sehvalue[2]+sehvalue[3]
               hex4=sehvalue[0]+sehvalue[1]
               asciivalue=toascii(imm,hex1)+toascii(imm,hex2)+toascii(imm,hex3)+toascii(imm,hex4)
               imm.log(" - Checking seh chain entry at 0x%08x, value %08x" % (chainentry[0],chainentry[1]))
               #see if string can be found in Metasploit pattern
               if asciivalue in mspattern:
                 PatternPos = mspattern.find(asciivalue)
                 imm.log("   => record is overwritten with Metasploit pattern after %d bytes" % (PatternPos))
                 g_typeofsploit=2
                 g_offset=PatternPos
               if asciivalue in mspattern.lower():
                 PatternPos = mspattern.lower().find(asciivalue)
                 imm.log("   => record is overwritten with lowercase Metasploit pattern after %d bytes" % (PatternPos))
                 g_typeofsploit=2
                 g_offset=PatternPos
               if asciivalue in mspattern.upper():
                 PatternPos = mspattern.upper().find(asciivalue)
                 imm.log("   => record is overwritten with uppercase Metasploit pattern after %d bytes" % (PatternPos))
                 g_typeofsploit=2
                 g_offset=PatternPos
               if (asciivalue=="AAAA" or asciivalue=="BBBB"):
                 imm.log("   => record is overwritten with %s" % (asciivalue))
                 guessstart(asciivalue,2)
               if (asciivalue=="aaaa" or asciivalue=="bbbb"):
                 imm.log("   => record is overwritten with %s (lowercase)" % (asciivalue))
                 guessstart(asciivalue,2)
               nrofentries=nrofentries+1
         #see if sehchain is overwritten with unicode pattern. We need at least 2 entries for the easy way
        if	nrofentries > 1:
            pos=0
            previousentry="01010101"
            for chainentry in thissehchain:
                if (pos > 0):
                    thisaddr=tohex(chainentry[0])
                    if (thisaddr[0]=="0" and thisaddr[1]=="0" and thisaddr[4]=="0" and thisaddr[5]=="0" and previousentry[0]=="0" and previousentry[1]=="0" and previousentry[4]=="0" and previousentry[5]=="0"):
                       #unicode address
                       #try to reassemble entire string
                       patstring=thisaddr[6]+thisaddr[7]+ thisaddr[2]+thisaddr[3]+ previousentry[6]+previousentry[7]+previousentry[2]+previousentry[3]
                       try:
                         ascipat=toascii(imm,thisaddr[6]+thisaddr[7])+toascii(imm,thisaddr[2]+thisaddr[3])+toascii(imm,previousentry[6]+previousentry[7])+toascii(imm,previousentry[2]+previousentry[3])
                         imm.log("    *** Unicode pattern found : %s => %s *** " % (patstring,ascipat))
                       except:
                          pass
                       if ascipat in mspattern:
                           PatternPos = mspattern.find(ascipat)
                           imm.log("   => record is overwritten with Unicode Metasploit pattern at position %d" % (PatternPos))
                           g_typeofsploit=3
                           g_offset=PatternPos
                       if ascipat in mspattern.lower():
                           PatternPos = mspattern.lower().find(ascipat)
                           imm.log("   => record is overwritten with Unicode lowercase Metasploit pattern at position %d" % (PatternPos))
                           g_typeofsploit=3
                           g_offset=PatternPos
                       if ascipat in mspattern.upper():
                          PatternPos = mspattern.upper().find(ascipat)
                          imm.log("   => record is overwritten with Unicode uppercase Metasploit pattern at position %d" % (PatternPos))
                          g_typeofsploit=3
                          g_offset=PatternPos
                previousentry=tohex(chainentry[1])
                pos=pos+1
        if nrofentries == 1:
            #only one entry, so read one from chainentry, other from stack
            thisaddr=tohex(chainentry[1])
            if (thisaddr[0]=="0" and thisaddr[1]=="0" and thisaddr[4]=="0" and thisaddr[5]=="0"):
                #SE Handler is unicode. Read previous 4 bytes too
                nsehaddress=chainentry[0]
                nsehvalue=imm.readMemory(nsehaddress,4)
                b1=toascii(imm,thisaddr[6]+thisaddr[7])
                b2=toascii(imm,thisaddr[2]+thisaddr[3])
                ascuni=nsehvalue[0] + nsehvalue[2] + b1 + b2
                if ascuni in mspattern:
                  PatternPos = mspattern.find(ascuni)
                  g_typeofsploit=3
                  g_offset=PatternPos
                  imm.log(" - SEH Chain overwritten with unicode pattern %s :" % ascuni)
                  imm.log("        NSEH overwritten after %d bytes" % (PatternPos))
                  imm.log("        SE Handler overwritten 2 bytes after (offset %d - expanded to unicode, this becomes 4 bytes) " % (PatternPos+2))
        imm.log("   Evaluated %d SEH entries" % nrofentries)
      else:
        if len(args) == 2:
          #do pattern_offset search
          pattern_offset(args[1],8000,imm)
      imm.log("-------------------------------------------------------------------------")
      if args[0] == "findmsp":
        return "Done"


    if args[0] == "suggest":
        imm.log("Exploit payload information and suggestions :")
        imm.log("---------------------------------------------")
        if g_typeofsploit==0:
            imm.log(" [+] Sorry, you'll have to analyse this vulnerability manually")
        if g_typeofsploit==1:
            imm.log(" [+] Type of exploit : Direct RET overwrite (EIP is overwritten)")
            imm.log("     Offset to direct RET : %d " % g_offset)
            imm.log(" [+] Payload found at %s " % g_jumpreg)
            imm.log("     Offset to register : %d " % g_regpos)
            imm.log(" [+] Payload suggestion (perl) :")
            if g_regpos > g_offset:
               imm.log('     my $junk="\\x41" x %d; ' % g_offset)
               if g_regoff=="":
                 imm.log('     my $ret = XXXXXXXX; #jump to %s - run  !pvefindaddr j -r %s -n  to find an address' % (g_jumpreg,g_jumpreg))
               else:
                 imm.log('     my $ret = XXXXXXXX; #jump to %s+%s - run  !pvefindaddr jo -r %s -n to find an address' % (g_jumpreg,g_regoff,g_jumpreg))
               posdiff=int(g_regpos)-int(g_offset)-4
               if posdiff > 0:
                 imm.log('     my $padding = "\\x90" x %d; ' % posdiff)
                 imm.log('     my $shellcode="<your shellcode here>";')
                 imm.log('     my $payload=$junk.$ret.$padding.$shellcode;')
               else:
                 imm.log('     my $shellcode="<your shellcode here>";')
                 imm.log('     my $payload=$junk.$ret.$shellcode;')
            else:
                imm.log('     my $junk="\\x41" x %d; ' % g_regpos)
                maxbytes=int(g_offset)-int(g_regpos)-4
                imm.log('     my $shellcode="<your shellcode here, max %d bytes>";' % maxbytes)
                imm.log('     my $morejunk="\\x90" x (%d-length($shellcode));' % maxbytes)
                imm.log('     my $ret = XXXXXXXX; #jump to %s - run  !pvefindaddr j -r %s -n  to find an address' % (g_jumpreg,g_jumpreg))
                imm.log('     my $payload = $junk.$shellcode.$morejunk.$ret;')
            imm.log(' [+] Read more about this type of exploit at')
            imm.log('     http://www.corelan.be:8800/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/')
        if g_typeofsploit==2:
            imm.log(" [+] Type of exploit : SEH (SE Handler is overwritten)")
            nseh=int(g_offset)-4
            imm.log("     Offset to next SEH : %d " % nseh)
            imm.log("     Offset to SE Handler : %d " % g_offset)
            imm.log(" [+] Payload suggestion (perl) :")
            imm.log('     my $junk="\\x41" x %d; ' % nseh)
            imm.log('     my $nseh="\\xeb\\x06\\x90\\x90";')
            imm.log('     my $seh= XXXXXXXX;  #pop pop ret - use !pvefindaddr p -n    to find a suitable address')
            imm.log('     my $nops="\\x90" x 24;')
            imm.log('     my $shellcode="<your shellcode here>";')
            imm.log('     my $payload = $junk.$nseh.$seh.$nops.$shellcode;')
            imm.log(' [+] Read more about this type of exploit at ')
            imm.log('     http://www.corelan.be:8800/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/')
        if g_typeofsploit==3:
            imm.log(" [+] Type of exploit : SEH Unicode (SE Handler is overwritten with Unicode pattern")
            imm.log("     Offset to next SEH : %d " % g_offset)
            imm.log(" [+] Payload suggestion (perl) :")
            imm.log('     my $junk="\\x41" x %d; ' % g_offset)
            imm.log('     my $nseh=\\x??\\x??;  #find 2 instructions that, when converted to \\x??\\x00\\x??\\x00 will not do any harm')
            imm.log('     my $seh= \\x??\\x??;  #find pop pop ret (Unicode compatible). use  !pvefindaddr p  to find a suitable address')
            imm.log('     my $padding = .... ;  #write venetian code to point a register to the beginning of the shellcode')
            imm.log('     my $jmp = "\\x50\\x6d\\xc3";  #write venetion code to jump to the register (example shown here = push eax + ret)')
            imm.log('     my $shellcode="XXXXXXXXXXXX...";  #venetian shellcode')
            imm.log('     my $payload=$junk.$nseh.$seh.$padding.$jmp.$shellcode;')
            imm.log(' [+] Read more about this type of exploit at ')
            imm.log('     http://www.corelan.be:8800/index.php/2009/11/06/exploit-writing-tutorial-part-7-unicode-from-0x00410041-to-calc/')
        imm.log("---------------------------------------------------------------")
        return "Done"


    if args[0] == "update" or args[0]=="selfupdate":
        updatetype = "release"
        if (__VERSION__.find("dev") > -1):
            updatetype= "trunk"
        if len(args) > 1:
           if args[1].lower() == "get":
              getupdate(imm,updatetype)
           else:
              findupdate(imm)
        else:
           if args[0]=="update":
             findupdate(imm)
           if args[0]=="selfupdate":
             getupdate(imm,updatetype)
        return "Done checking for updates"


    if args[0] == "compare":
     if len(args) > 1:
      filename="compare.txt"
      resetfile(filename)
      imm.log("---------------------------------------------")
      imm.log(" Compare memory with bytes in file")
      imm.log("---------------------------------------------")
      imm.log(" Reading file %s (ascii)..." % args[1])
      if os.path.isfile(args[1]):
        try:
            srcdata=[]
            tagresults=[]
            srcfile = open(args[1],"rb")
            content = srcfile.readlines()
            srcfile.close()
            for eachLine in content:
               srcdata += eachLine
            imm.log(" Read %d bytes from file" % len(srcdata))
            cnt=0
            maxcnt=len(srcdata)
            startat=""
            if (maxcnt < 8):
                Imm.log(" File contains less than 8 bytes !")
            if len(args) == 3:
                if (len(args[2]) == 10):
                   startat=args[2].replace("0x","")
                   startat=startat.replace("0X","")
                else:
                   startat=args[2]
                imm.log(" Compare will only look at address %s " % startat)
            else:
                imm.log(" Starting search in memory")
            linecount=0
            while (cnt < maxcnt):
              try:
                 #group per 8 bytes to get first line with 8 bytes (tag to search for)
                 btcnt=0
                 hexstr=""
                 while ((btcnt < 8) and (cnt < maxcnt)):
                   if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
                       hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
                   else:
                       hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
                   hexstr += hexchar
                   btcnt=btcnt+1
                   cnt=cnt+1
                 linecount=linecount+1
                 if ((linecount == 1) and (startat == "")):
                    imm.log("   -> searching for "+hexstr)
                    toSearch = hexstr.replace(" ",'\\x').decode('string_escape')
                    toSearch = toSearch.decode('string_escape')
                    tagresults=imm.search( toSearch )
                    if (len(tagresults) == 0):
                       imm.log(" Could not find code in memory !")
                       return
              except:
                cnt=cnt+1
                pass
            imm.log(" Comparing bytes from file with memory :")
            comparetable=imm.createTable('pvefindaddr Memory comparison results',['Address','Status','Type'])
            for tres in tagresults:
                memcompare(imm,tohex(tres),srcdata,comparetable,"ascii")
            if (startat <> ""):
                memcompare(imm,startat,srcdata,comparetable,"ascii")
        except:
            imm.log(" ** Unable to read file **")
        imm.log("")
        imm.log("")
        imm.log(" Reading file %s (expanding to unicode)..." % args[1])
        try:
            srcdata=[]
            tagresults=[]
            srcfile = open(args[1],"rb")
            content = srcfile.readlines()
            srcfile.close()
            for eachLine in content:
               srcdata += eachLine
            imm.log(" Read %d bytes from file" % len(srcdata))
            imm.log(" Expanding to unicode")
            unisrcdata=[]
            nullbyte="0"
            for eachByte in srcdata:
                eachByte+=struct.pack('B', 0)
                unisrcdata+=eachByte
            srcdata=unisrcdata
            cnt=0
            maxcnt=len(srcdata)
            imm.log(" Unicode expanded to %d bytes" % maxcnt)
            startat=""
            if (maxcnt < 16):
                Imm.log(" File contains less than 16 bytes !")
            if len(args) == 3:
                if (len(args[2]) == 10):
                   startat=args[2].replace("0x","")
                   startat=startat.replace("0X","")
                else:
                   startat=args[2]
                imm.log(" Compare will only look at address %s " % startat)
            else:
                imm.log(" Starting search in memory")
            linecount=0
            while (cnt < maxcnt):
              try:
                 #group per 16 bytes to get first line with 16 bytes (tag to search for)
                 btcnt=0
                 hexstr=""
                 while ((btcnt < 16) and (cnt < maxcnt)):
                   if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
                       hexchar=hex(ord(srcdata[cnt])).replace('0x', '\\x0')
                   else:
                       hexchar = hex(ord(srcdata[cnt])).replace('0x', '\\x')
                   hexstr += hexchar
                   btcnt=btcnt+1
                   cnt=cnt+1
                 linecount=linecount+1
                 if ((linecount == 1) and (startat == "")):
                    imm.log("   -> searching for "+hexstr)
                    toSearch = hexstr.replace(" ",'\\x').decode('string_escape')
                    toSearch = toSearch.decode('string_escape')
                    tagresults=imm.search( toSearch )
                    if (len(tagresults) == 0):
                       imm.log(" Could not find code in memory !")
                       return
              except:
                cnt=cnt+1
                pass
            imm.log(" Comparing bytes from file with memory :")
            for tres in tagresults:
                memcompare(imm,tohex(tres),srcdata,comparetable,"unicode")
            if (startat <> ""):
                memcompare(imm,startat,srcdata,comparetable,"unicode")
        except:
            imm.log(" ** Unable to read file **")
      else:
         imm.log(" ************************** ",highlight=1)
         imm.log(" ** File does not exist !** ",highlight=1)
         imm.log(" ************************** ",highlight=1)


    if args[0] == "peb":
        #find peb
		#structure http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB.html
        imm.log("")
        PEB = imm.getPEBaddress()
        if PEB == 0:
            imm.log("No PEB")
        else:
            imm.log("PEB at 0x%08x" % PEB,address=PEB)
            ias = tocontent(imm.readMemory(PEB+0x0,1))
            if (ias	== "00"):
                iasstr="No"
            else:
                iasstr="Yes"
            imm.log("  InheritedAddressSpace: %s" % iasstr)
            rifeo = tocontent(imm.readMemory(PEB+0x1,1))
            if (rifeo == "00"):
                rifeostr="No"
            else:
                rifeostr="Yes"
            imm.log("  ReadImageFileExecOptions: %s " % rifeostr)
            bd = tocontent(imm.readMemory(PEB+0x2,1))
            if (bd == "00"):
                bdstr ="No"
            else:
                bdstr ="Yes"
            imm.log("  BeingDebugged: %s" % bdstr)
            spare = tocontent(imm.readMemory(PEB+0x3,1))
            if (spare == "00"):
                sparestr ="No"
            else:
                sparestr ="Yes"
            imm.log("  Spare: %s" % sparestr)

            hmutant = tocontent(imm.readMemory(PEB+0x4,4))
            imm.log("  Handle: %s" % (hmutant))
            ba = tocontent(imm.readMemory(PEB+0x8,4))
            imm.log("  ImageBaseAddress: %s" % (ba))
            ldr = tocontent(imm.readMemory(PEB+0xc,4))
            imm.log("  Ldr: %s" % ldr)
            #imm.log("  Ldr.Initialized:")
            #imm.log("  Ldr.InInitializationOrderModuleList: ")
            #imm.log("  Ldr.InLoadOrderModuleList:")
            #imm.log("  Ldr.InMemoryOrderModuleList:")
            #modules
            allmodules=imm.getAllModules()
            imm.log("          Base  Size     Module")
            for key in allmodules.keys():
                mod=imm.getModule(key)
                mzbase=mod.getBaseAddress()
                imm.log("    0x%08x  %d  %s" % (mzbase,mod.getSize(),mod.getPath()))
            ssd = tocontent(imm.readMemory(PEB+0x14,4))
            imm.log("  SubSystemData: %s" % ssd)
            ph = tocontent(imm.readMemory(PEB+0x18,4))
            imm.log("  ProcessHeap: %s" % ph)
            pp = tocontent(imm.readMemory(PEB+0x10,4))
            imm.log("  ProcessParameters: %s" % pp)
            imm.log("")

    if (args[0] == "assemble"):
        imm.log("Opcode results : ")
        imm.log("---------------- ")
        cnt=1
        cmdInput=""
        allopcode=""
        encodecmd=""
        encodebad=""
        curpos=0
        while (cnt < len(args)):
           if (args[cnt].lower() == "encode"):
              curpos=cnt
              cnt=len(args)
           else:
              cmdInput=cmdInput+args[cnt]+" "
           cnt=cnt+1
        if curpos > 0:
            if curpos==len(args)-1:
                encodecmd="ascii"
            if curpos==len(args)-2:
                encodecmd=args[curpos+1]
            if curpos==len(args)-3:
                encodecmd=args[curpos+1]
                encodebad=args[curpos+2]
        cmdInput=cmdInput.replace("'","")
        cmdInput=cmdInput.replace('"','')
        splitter=re.compile('#')
        instructions=splitter.split(cmdInput)
        for instruct in instructions:
            try:
               assembled=imm.assemble( instruct )
               strAssembled=""
               for assemOpc in assembled:
                  if (len(hex(ord(assemOpc)))) == 3:
                     subAssembled = "\\x0"+hex(ord(assemOpc)).replace('0x','')
                     strAssembled = strAssembled+subAssembled
                  else:
                     strAssembled =  strAssembled+hex(ord(assemOpc)).replace('0x', '\\x')
               if len(strAssembled) < 30:
                  imm.log(" %s = %s" % (instruct,strAssembled))
                  allopcode=allopcode+strAssembled
               else:
                  imm.log(" %s => Unable to assemble this instruction !" % instruct,highlight=1)
            except:
               imm.log("   Could not assemble %s " % instruct)
               pass
        imm.log(" Full opcode : %s " % allopcode)
        if (encodecmd != ""):
            imm.log(" Invoking encoder...")
            imm.log("")
            encodeargs=[]
            encodeargs.append("doencode")
            encodeargs.append(encodecmd)
            encodeargs.append(allopcode.replace('\\x',''))
            encodeargs.append(encodebad)
            doencode(encodeargs)


    if args[0] == "offset":
        endaddr=[]
        if len(args) == 3:
            regs = imm.getRegs()
            startaddr=args[1]
            startreg=""
            startregname=""
            endaddr.append(args[2])
            endreg=""
            regaction=""
            if (len(startaddr)==3):
                #perhaps this is a register
                #get the value of the register
                for reg in regs:
                    if reg.upper() == startaddr.upper():
                        startaddr=tohex(regs[reg])
                        startreg=" ("+reg+")"
                        startregname=reg
            if (len(endaddr[0])==3):
                #perhaps this is a register
                #get the value of the register
                for reg in regs:
                    if reg.upper() == endaddr[0].upper():
                        endaddr[0]=tohex(regs[reg])
                        endreg=" ("+reg+")"
            if (len(endaddr[0])==16):
                #search pattern
                strb=binascii.a2b_hex(endaddr[0])
                opcodej=[strb]
                imm.log(" - Trying to locate custom search pattern, please wait...")
                imm.updateLog()
                for opjc in opcodej:
                    addys=imm.search( opjc )
                    results += addys
                nrres=0
                if results:
                    nrres=len(results)
                imm.log(" - Number of locations found : %d" % nrres)
                del endaddr[0]
                for res in results:
                    endaddr.append(tohex(res))
            try:
                for endad in endaddr:
                    imm.log("[+] Calculating offset between %s%s and %s%s" % (startaddr,startreg,endad,endreg))
                    val1=addresstoint(startaddr)
                    val2=addresstoint(endad)
                    diff=0
                    if val1 > val2:
                       diff=val1-val2
                    else:
                       diff=val2-val1
                    result=tohex(diff)
                    imm.log("    -> Offset : %d bytes (0x%s)" % (diff,result))
                    if val1 > val2:
                        imm.log("       Warning : negative offset, so backward jump needed!")
                        negjmp=tohex(4294967296-diff)  #=(FFFFFFFF+1) - value
                        negjmpbytes="\\x"+ negjmp[6]+negjmp[7]+"\\x"+negjmp[4]+negjmp[5]+"\\x"+negjmp[2]+negjmp[3]+"\\x"+negjmp[0]+negjmp[1]
                        imm.log("       Jump offset : %s" % negjmpbytes)
                        regaction="sub"
                    else:
                        if result[0]=="0" and result[1]=="0" and result[2]=="0" and result[3]=="0" and result[4]=="0" and result[5]=="0":
						    posjmpbytes="\\x"+result[6]+result[7]
                        else:
                            posjmpbytes="\\x"+ result[6]+result[7]+"\\x"+result[4]+result[5]+"\\x"+result[2]+result[3]+"\\x"+result[0]+result[1]
                        imm.log("       Jump offset : %s" % posjmpbytes)
                        regaction="add"
                    strTotalOpcode=""
                    if startregname != "":
                        strAsm=regaction+" "+startregname+","+result
                        strToAsm=[]
                        strToAsm.append(strAsm)
                        strToAsm.append("jmp " + startregname)
                        for strAsmThis in strToAsm:
                           assembled=imm.Assemble( strAsmThis )
                           strAssembled=""
                           for assemOpc in assembled:
                              if (len(hex(ord(assemOpc)))) == 3:
                                 subAssembled = "\\x0"+hex(ord(assemOpc)).replace('0x','')
                                 strAssembled = strAssembled+subAssembled
                              else:
                                 strAssembled =  strAssembled+hex(ord(assemOpc)).replace('0x', '\\x')
                           imm.log("       Assembly : %s, Opcode : %s" % (strAsmThis.lower(),strAssembled))
                           strTotalOpcode=strTotalOpcode+strAssembled
                        imm.log("       Full opcode : " + strTotalOpcode)
                    imm.log("")
            except:
                imm.log(" !! Unable to calculate offset. Verify input and try again")

    if (args[0] == "encode"):
        doencode(args)

    if (args[0] == "info"):
        addr=""
        addrname=""
        if len(args) > 1:
            if (len(args[1]) == 10):
               addr=args[1].replace("0x","")
               addr=addr.replace("0X","")
            else:
			    #check if it is a register
                regs = imm.getRegs()
                for reg in regs:
                    if reg.upper() == args[1].upper():
                        addr=tohex(regs[reg])
                        addrname=" ("+reg+")"
                if addr=="":
                    addr=args[1]
            imm.log("Information about address %s%s : " % (addr,addrname))
            imm.log(addressinfo(addresstoint(addr)))
            imm.log(addressspec(addr))
            try:
                op = imm.Disasm( addresstoint(addr) )
                opstring=op.getDisasm()
                imm.log("Instruction at %s : %s" % (addr,opstring))
            except:
                pass
        else:
            imm.log("You forgot to specify an address or register")

    if(args[0] == "find"):
      dofind(imm,args,modulefilter)

    if(args[0] == "fd"):
        filename="fd.txt"
        resetfile(filename)
        writemodinfo(filename)
        startaddr=1
        found=0
        allownull=0
        doread=1
        if len(args)==2:
            if args[1].lower()=="allownull":
                allownull=1
        imm.log("Started looking for addresses, please wait...")
        imm.updateLog()
        maxval=2147483645
        while ((startaddr < maxval) and (found < 10)):
            daddr=startaddr*2
            try:
                if (allownull==0):
                    starta=tohex(startaddr)
                    dstarta=tohex(daddr)
                    doread=1
                    if ((starta[0]=="0" and starta[1]=="0") or (starta[2]=="0" and starta[3]=="0") or (starta[4]=="0" and starta[5]=="0") or (starta[6]=="0" and starta[7]=="0")):
                        doread=0
                    if ((dstarta[0]=="0" and dstarta[1]=="0") or (dstarta[2]=="0" and dstarta[3]=="0") or (dstarta[4]=="0" and dstarta[5]=="0") or (dstarta[6]=="0" and dstarta[7]=="0")):
                        doread=0
                else:
                    doread=1
                if doread==1:
                   imm.updateLog()
                   startval=imm.readMemory(startaddr,4)
                   dval=imm.readMemory(daddr,4)
                   if (startval <> "") and (dval <> ""):
                      extrastring1=addressinfo(startval)
                      extrastring2=addressinfo(dval)
                      imm.log(" Addresses found :")
                      imm.log("   Address : 0x%08x %s" % (startaddr,extrastring1))
                      imm.log("   Double of address :  0x%08x %s" % (daddr,extrastring2))
                      tofile("Found 2 possible addresses :",filename)
                      tofile("   - " + tohex(startaddr)+" "+extrastring,filename)
                      tofile("   - " + tohex(daddr)+" "+extrastring,filename)
                      imm.log("")
                      imm.updateLog()
                      found=found+1
                startaddr=startaddr+1
                nextaddr=tohex(startaddr)
                if nextaddr[4]=="0" and nextaddr[5]=="0" and nextaddr[6]=="0" and nextaddr[7]=="0":
                    imm.log("Progress update - reached address %s ..." % nextaddr)
                    imm.updateLog()
            except:
                imm.updateLog()
                startaddr=startaddr+1
                nextaddr=tohex(startaddr)
                if nextaddr[4]=="0" and nextaddr[5]=="0" and nextaddr[6]=="0" and nextaddr[7]=="0":
                    imm.log("Progress update - reached address %s ..." % nextaddr)
                    imm.updateLog()
                pass
        if found==0:
            imm.log("Sorry, no usable addresses found")
        else:
            imm.log("%d addresses found" % found)
        return "Search complete, %d pointers found" % found


    if(args[0] == "rop"):
        filename="rop.txt"
        stackpivotfile="rop_stackpivot.txt"
        progressid=tohex(imm.getDebuggedPid())
        progressfile="_rop_progress_"+imm.getDebuggedName()+"_"+progressid+".log"
        imm.log("-----------------------")
        imm.log(" ROP Gadget generation")
        imm.log("-----------------------")
        imm.log("[+] ROP progress will be written to %s" % progressfile)
        imm.updateLog()
        resetfile(progressfile)
        resetfile(stackpivotfile)
        tofile("-------------------------------------------",stackpivotfile)
        tofile("Possibly interesting stack pivot pointers :",stackpivotfile)
        tofile("-------------------------------------------",stackpivotfile)
        thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
        tofile("ROP Gadget generation process started at " + thistimestamp+"\n",progressfile)
        if len(g_modules)==0:
            moduleinfo()
        instrfilter=" "
        opcodej=[]
        mbase=0
        maxretval=32
        mutations=0
        goodgadgets=0
        dosplit=0
        dodeep=0
        ignorefixup=0
        customendwith=""
        argstr=""
        cnt=1
        while cnt < len(args):
            if args[cnt]=='-f':
                if cnt < (len(args)-1):
                    instrfilter=args[cnt+1]
            if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    maxretval=int(args[cnt+1])
            if args[cnt]=='-s':	dosplit=1
            if args[cnt]=='-d': dodeep=1
            if args[cnt]=='-i': ignorefixup=1
            if args[cnt]=='-c':
                cnt2=cnt
                while cnt2 < (len(args)-1):
                    if args[cnt2+1][:1] <> "-":
                       customendwith=customendwith+" "+args[cnt2+1].upper()
                    cnt2=cnt2+1
            cnt=cnt+1
        customendwith=customendwith.strip()
        cinstrparts=customendwith.split('#')
        if customendwith <> "":
             imm.log("[+] You have specified %d custom gadget end instruction(s) : %s" % (len(cinstrparts),customendwith))
        if modulefilter <> "":
          if dosplit==1:
             imm.log("[+] You have specified a module filter and enabled 'split' (-s)")
             imm.log("    Split functionality won't make a difference, so option has been removed again")
             dosplit=0
          if (noos==1):
              imm.log("[+] Module filter and option to exclude OS dll's set. If module is an OS dll, it will not be excluded")
          imm.log("[+] Finding module that starts with %s" % modulefilter)
          for mname in g_modules:
              mnamentry=mname.split('\t')
              if mnamentry[0].lower().startswith(modulefilter.lower()):
                  mfound=1
                  modulefilter=mnamentry[0].lower()
                  mbase=int(mnamentry[2])
                  mtop=int(mnamentry[4])
                  isaslr=int(mnamentry[6])
                  isfixup=int(mnamentry[8])
                  modversion=mnamentry[9]
                  filename=getropfilename(modulefilter)
        if customendwith == "":
           opcodej.append("RET\n")
        else:
           inscnt=0
           while inscnt < len(cinstrparts):
              opcodej.append(cinstrparts[inscnt].strip().upper())
              inscnt=inscnt+1
        if dosplit==0:
           resetfile(filename)
           writemodinfo(filename)
           imm.log("[+] Preparing log file %s" % filename)
           tofile("-" * 80,filename)
           tofile(" ROP gadgets - Relatively safe/basic instructions ",filename)
           tofile("-" * 80,filename)
           tofile("",filename)
        else:
           #create individual files
            for mname in g_modules:
               mnamentry=mname.split('\t')
               modname=mnamentry[0]
               if modname.upper().find(modulefilter.upper()) >= 0:
                  if (noos==0) or (noos==1 and isosmodule(modname)==0):
                    thisfilename=getropfilename(modname)
                    imm.log("[+] Preparing log file %s" % thisfilename)
                    tofile("Preparing log file " + thisfilename,progressfile)
                    imm.updateLog()
                    resetfile(thisfilename)
                    writemodinfo(thisfilename)
                    tofile("-" * 80,thisfilename)
                    tofile(" ROP gadgets - Relatively safe/basic instructions ",thisfilename)
                    tofile("-" * 80,thisfilename)
                    tofile("",thisfilename)
        c1=2
        imm.updateLog()
        if customendwith=="":
          while c1 <= maxretval:
            opcodej.append("RET " + tohexbyte(c1)+"\n")
            c1=c1+2
        aslrfilt="ASLR: ** NO"
        fixupfilt="FIXUP: ** NO"
        isfixup=0
        imm.updateLog()
        isaslr=0
        mfound=0
        modversion=""
        if (dodeep==1):
            imm.log("[+] Deep search enabled. Possibly interesting gadgets will be written to %s" % filename)
        if (noos==1):
            imm.log("[+] Dll's residing in the Windows folder will be excluded.")
            if (dosplit==0):
               tofile(" [+] Excluding dll's from Windows folder",filename)
        if (ignorefixup==1):
            tofile(" [+] Excluding pointers from modules that have fixup flag set",filename)
            imm.log("[+] Excluding pointers from modules that have fixup flag set")
        if modulefilter <> "" and mbase > 0:
            imm.log("[+] Module filter set to '%s', at baseaddress 0x%s" % (modulefilter,tohex(mbase)))
            tofile(" [+] Module filter set to '" + modulefilter+"' "+modversion,filename)
            aslrfilt=" "
            fixupfilt=" "
            if isaslr==1:
                imm.log("    ! Module is aslr aware - you'd better start looking for memory leaks now :-)")
                imm.log("      For your convenience, output will contain offset to base")
            else:
                imm.log("    Module is not aslr aware")
        else:
            imm.log("[+] No module filter set ")
        imm.updateLog()
        tofile("",filename)
        if modulefilter <> "" and mbase==0:
            imm.log(" [-] Warning : modulefilter set, but no matching module found !")
        instrfilter=instrfilter.upper().lstrip().rstrip().replace('"','')
        if instrfilter.replace(" ","") <> "":
            imm.log("[+] Instruction filter set to '%s' " % instrfilter)
            if dosplit==0:
               tofile(" [+] Instruction filter set to '" + instrfilter+"'",filename)
        if dosplit==1:
            imm.log("[+] Output will be written to individual files (one file per module)")
        else:
            imm.log("[+] Output will be written to %s" % filename)
        imm.log("Searching for possible ROP gadgets...please wait")
        imm.updateLog()
        imm.updateLog()
        nrchains=0
        nrgood=0
        addys=[]
        stackpivots=[]
        pivottable=imm.createTable('pvefindaddr ROP Stack Pivot',['Address','Offset/Register','Instruction','Module','Info'])
        cinstructs0=""
        cinstructs=""
        cinstructs2=""
        opnr=len(opcodej)
        thisnr=1
        offsetcnt=0
        #get all search results
        imm.log(" - Searching memory for gadgets, please wait...")
        tofile("\nStarted generating rop gadgets",progressfile)
        scnt=1
        for searchcmd in opcodej:
            imm.log("   Search sequence %d / %d (%s)" % (scnt,opnr,searchcmd.strip()))
            tofile(" - Search sequence " + str(scnt)+"/"+str(opnr),progressfile)
            addys += imm.searchCommands(searchcmd.strip())
            scnt=scnt+1
            imm.updateLog()
        imm.log(" - Total number of pointers found in memory: %d " % len(addys))
        tofile("Total number of pointers found in memory : " + str(len(addys)),progressfile)
        imm.log(" - Filtering, verifying and mutating gadgets,please wait...")
        tofile("\nFiltering and mutating gadgets, this can take a long time.",progressfile)
        tofile("(Periodic updates will be written to this file... stay tuned !)",progressfile)
        imm.updateLog()
        adcnt=0
        tc=1
        totaladdys=len(addys)
        for ad1 in addys:
            adcnt=adcnt+1
            if adcnt > (tc*1000):
                thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
                tofile(" - Progress update : " + str(tc*1000) + " pointers processed (" + thistimestamp + ")",progressfile)
                tc=tc+1
            ad1=ad1[0]
            imm.updateLog()
            smodule=0
            #what module does this pointer belong to, and does it need to be examined ?
            thismodname=getmodnamefromptr(ad1)
            if thismodname <> "":
              isaslr=int(getmoduleprop(thismodname,"aslr"))
              isfixup=int(getmoduleprop(thismodname,"fixup"))
              mbase=int(getmoduleprop(thismodname,"base"))
              mtop=int(getmoduleprop(thismodname,"top"))
              #filtering modules ?
              if (modulefilter <> ""):
                if (modulefilter.upper()==thismodname.upper()):
                      smodule=1
                else:
                      smodule=0
              else:
                #no module filter
                smodule=1
                if (noos==1):
                    if(isosmodule(thismodname)==1):
                        smodule=0
                if (isaslr==1):
                    smodule=0
                if (ignorefixup==1) and (isfixup==1):
                    smodule=0
            if smodule==1:
                  imm.updateLog()
                  foundarr=[]
                  cinstr=0
                  #info=addressinfo(ad1)
                  #infovars=info.split(']')
                  #mname=infovars[0].replace("[","")
                  mname=getmodnamefromptr(ad1)
                  #get current instruction
                  op0 = imm.Disasm( ad1 )
                  opstring0=op0.getDisasm()
                  modstr="[Module : "+mname+"]"
                  instrnr=1
                  stopthisrop=0
                  datastr=""
                  allstring=""
                  backmax=1
                  tofindstr="RET"
                  gadgetcontains=0
                  if customendwith == "" and opstring0.upper().find(tofindstr) > -1:
                     gadgetcontains=1
                  if customendwith <> "":
                     cinstrcnt=0
                     while cinstrcnt < len(opcodej):
                          if opstring0.upper().find(opcodej[cinstrcnt].upper()) > -1:
                            gadgetcontains=1
                          cinstrcnt=cinstrcnt+1
                  if gadgetcontains==1:
   				    #jump back up to 8 instructions
                    #then shift one byte at a time
                    #and skip the chains that do not end with RET/custom end instruction
                    #or contain invalid instructions
                    while backmax < 8:
                      try:
                        opstart=imm.DisasmBackward(ad1,backmax)
                        opadstart=opstart.getAddress()
                        #get number of bytes between ad1 and current address
                        maxbytes=ad1-opadstart
                        mutations=mutations+1
                        #max bytes to walk = maxbytes-2
                        #max instructions to read forward : 8
                        bytecnt=0
                        while bytecnt < maxbytes:
                            #
                            startad=opadstart+bytecnt
                            thisinstrline=""
                            icnt=0
                            stopthisrop=0
                            retfound=0
                            nrpush=0
                            nrpop=0
                            basicops=0
                            basicinstr=["POP","PUSH","MOV ","INC ","DEC ","RET","XOR ","ADD ","SUB ","ADC ","SBB ","NOP","CMP ","XCHG","LEA ","MOV DWORD PTR SS:\[E","MOV DWORD PTR DS:\[E","CALL EAX","CALL EBX","CALL ECX","CALL EDX","CALL EBP","CALL ESI","CALL EDI","CALL ESP"]
                            basicexcl=["ADD BYTE","SUB DWORD PTR","PUSH DWORD PTR","JMP",".","IRETD","RETF"]
                            mustreachexcl=0
                            while icnt < 8 and stopthisrop==0 and retfound==0:
                                try:
                                   op=imm.DisasmForward(startad,icnt)
                                   opstring=op.getDisasm()
                                   thisinstrline=thisinstrline+" # " + opstring
                                   gadgetcontains=0
                                   if customendwith == "" and opstring.upper().find(tofindstr) > -1:
                                      gadgetcontains=1
                                   if customendwith <> "":
                                      cinstrcnt=0
                                      while cinstrcnt < len(opcodej):
                                        if opstring.upper().find(opcodej[cinstrcnt].upper()) > -1:
                                            gadgetcontains=1
                                        cinstrcnt=cinstrcnt+1
                                   if gadgetcontains==1:
                                        retfound=1
                                   if opstring.upper().find("???") > -1:
                                        stopthisrop=1
                                   if opstring.upper().find("PUSH ") > -1:
                                        nrpush=nrpush+1
                                   if opstring.upper().find("PUSHAD") > -1:
                                        nrpush=nrpush+1
                                   if opstring.upper().find("POP ") > -1:
                                        nrpop=nrpop+1
                                   if opstring.upper().find("POPAD") > -1:
                                        nrpop=nrpop+1
                                   for binstr in basicinstr:
                                        if opstring.upper().find(binstr.upper()) > -1:
                                            mustreachexcl=0
                                            for bexcl in basicexcl:
                                                if opstring.upper().find(bexcl.upper()) == -1:
                                                   mustreachexcl=mustreachexcl+1
                                            if mustreachexcl==len(basicexcl):
                                                basicops=basicops+1
                                except:
                                    stopthisrop=1
                                icnt=icnt+1
                                #is this a good series of instructions ?
                                if retfound==1:
                                   if isaslr==1 and mbase > -1:
                                      #get offset to base as well
                                      thisbaseaddr=mbase
                                      thoffset=startad-mbase
                                      datastr="0x"+tohex(startad)+" (base+0x" +tohex(thoffset)+") : "
                                   else:
                                      datastr="0x"+tohex(startad)+" : "
	    						   #determine type of instructions
                                   cinstr=3
                                   #first filter out the ones we're not interested in
                                   if thisinstrline.upper().find("INT3") == -1:
                                     if thisinstrline.upper().find("LEAVE") > -1 or thisinstrline.upper().find("CALL") > -1 or thisinstrline.upper().find("JMP") > -1 or thisinstrline.upper().find("JE") > -1 or thisinstrline.upper().find("JNE") > -1 or thisinstrline.upper().find("JZ") > -1 or thisinstrline.upper().find("JNZ") > -1 or thisinstrline.upper().find("JB") > -1 or thisinstrline.upper().find("JNB") > -1 or thisinstrline.upper().find("JL") > -1  or thisinstrline.upper().find("JP") > -1 or thisinstrline.upper().find("JNL") > -1 or thisinstrline.upper().find("JG") > -1 or thisinstrline.upper().find("JO") > -1 or thisinstrline.upper().find("JA") > -1:
                                        cinstr=1
	  				    		        #if it's a call to interesting function, then log in separate list
                                        if thisinstrline.upper().find("KERNEL32") > -1 or thisinstrline.upper().find("NTDLL") > -1 or thisinstrline.upper().find("MSVCR") > -1 or thisinstrline.upper().find("USER32") > -1 or thisinstrline.upper().find("ADVAPI32") > -1 or thisinstrline.upper().find("SHELL32") > -1 or thisinstrline.upper().find("WININET") > -1 or thisinstrline.upper().find("IERTUTIL") > -1 or thisinstrline.upper().find("WSOCK") > -1 :
                                          cinstr=2
                                        #if we specified a custom end and custom end contains a CALL or LEAVE, then allow it
                                        if customendwith.upper().find("CALL") > -1 or customendwith.upper.find("LEAVE") > -1:
                                            cinstr=0
                                     if basicops == thisinstrline.count('#'):
                                          cinstr=0
                                     if thisinstrline.count('#') == 1:
                                          cintr=-1   #don't log, is just a RET
                                     else:
                                        if nonull==1:
                                            if ((addressspec(tohex(startad)).find("Null byte") > -1) or (addressspec(tohex(startad)).find("Unicode") > -1)):
                                                #nonull filter, but address contains null byte
                                                #don't log
                                                cinstr=-2
                                        #do we have match with instruction filter ?
                                        if thisinstrline.upper().find(instrfilter.upper()) > -1:
   					  		             #log if not logged already
                                         procadbefore=-1
                                         try:
                                            procadbefore=foundarr.index(startad)
                                         except:
                                            pass
                                         if procadbefore==-1:
                                             marker=""
                                             if nrpush > 1:
                                                marker=" {PUSH} "
                                             if nrpop > 1:
                                                marker=marker+" {POP} "
                                             if cinstr==0:
                                                #write to file
                                                if dosplit==0 and modulefilter=="":
                                                    tofile(datastr+marker+thisinstrline+" \t" + modstr+" "+addressspec(tohex(startad)),filename)
                                                else:
                                                    thisfilename=getropfilename(mname)
                                                    tofile(datastr+marker+thisinstrline+" \t" + modstr+" "+addressspec(tohex(startad)),thisfilename)
                                                nrgood=nrgood+1
                                             if cinstr==1:
                                                #write to array
                                                cinstructs+=datastr+marker+thisinstrline+" \t" + modstr+" "+addressspec(tohex(startad))+"\n"
                                                nrgood=nrgood+1
                                             if cinstr==2:
                                                #write to array, with function name
                                                funcparts=thisinstrline.split('&')
                                                funccall=""
                                                if len(funcparts) > 1:
                                                    funcstub=funcparts[1].split('.')
                                                    if len(funcstub) > 1:
                                                       funcname=funcstub[1].split('>')
                                                       funccall=funcname[0]+" : "
                                                cinstructs2+=datastr+marker+funccall+"[*] "+thisinstrline+" \t" + modstr+" "+addressspec(tohex(startad))+"\n"
                                                nrgood=nrgood+1
                                             if cinstr==3:
                                                #write to array
                                                cinstructs0+=datastr+marker+thisinstrline+" \t" + modstr+" "+addressspec(tohex(startad))+"\n"
                                                nrgood=nrgood+1
                                             #Stack pivot, add to pivot list
                                             if (cinstr > -1) and ( (thisinstrline.upper().find("ADD ESP,") == 3) or ((thisinstrline.upper().find("LEA ESP,") == 3)) or ((thisinstrline.upper().find("XCHG ESP,") == 3)) or ((thisinstrline.upper().find("XCHG EAX,ESP") == 3)) or ((thisinstrline.upper().find("XCHG EBX,ESP") == 3)) or ((thisinstrline.upper().find("XCHG ECX,ESP") == 3)) or ((thisinstrline.upper().find("XCHG EDX,ESP") == 3)) or ((thisinstrline.upper().find("XCHG EBP,ESP") == 3)) or ((thisinstrline.upper().find("XCHG EDI,ESP") == 3)) or ((thisinstrline.upper().find("XCHG ESI,ESP") == 3)) or ((thisinstrline.upper().find("MOV ESP,[EBP") == 3))):
                                                if (thisinstrline.upper().find("CALL") == -1) and (thisinstrline.upper().find("JMP") == -1):
                                                  #what is the offset or register ?
                                                  stackpivotfields=thisinstrline.upper().split(',')
                                                  if len(stackpivotfields) > 1:
                                                     stackpivotoffset=stackpivotfields[1].split('#')
                                                     #offset is now in stackpivotoffset[0]. Add to array and to table, unless it's instr reg,ESP
                                                     soffset=stackpivotoffset[0]
                                                     if soffset.strip()=="ESP":
                                                        soffsetparts=stackpivotfields[0].split(' ')
                                                        soffset=soffsetparts[len(soffsetparts)-1]
                                                     ainfo=addressspec(tohex(startad))
                                            	     pivottable.add(0,["%s"%(tohex(startad)),"%s"%(soffset),"%s"%(thisinstrline),"%s"%(mname),"%s"%(ainfo)])
                                                     tofile("0x" + tohex(startad)+" : " + soffset + " : \t" + thisinstrline + " - " + mname + " - " + ainfo,stackpivotfile)
                                             #add address to "found" array
                                             foundarr.append(startad)
                                             goodgadgets=goodgadgets+1
                            bytecnt=bytecnt+1
                      except:
                        pass
                      backmax=backmax+1
                    imm.updateLog()
        tofile("Finished filtering & mutation process",progressfile)
        imm.log("   Number of gadgets & attempted mutations : %d" % (mutations))
        if goodgadgets > 0:
          imm.log("   Number of good gadgets (before filtering on null bytes, if required): %d" % (goodgadgets),highlight=1)
        else:
          imm.log("   Number of good gadgets (before filtering on null bytes, if required): %d" % (goodgadgets))
        imm.updateLog()
        #write remaining entries only if deep mode is enable
        if dodeep==1:
          tofile("\nDumping possibly interesting gadgets to " + filename,progressfile)
          tofile(" ",filename)
          tofile("-" * 80,filename)
          tofile(" ROP gadgets - Possible interesting gadgets...",filename)
          tofile("-" * 80,filename)
          cis=cinstructs0.split('\n')
          for cielem in cis:
            tofile(cielem,filename)
          tofile(" ",filename)
          tofile("-" * 80,filename)
          tofile(" ROP gadgets - With Jumps/Calls/... to possibly interesting functions...",filename)
          tofile("-" * 80,filename)
          cis=cinstructs2.split('\n')
          for cielem in cis:
            tofile(cielem,filename)
          tofile(" ",filename)
          tofile("-" * 80,filename)
          tofile(" ROP gadgets - With Jumps/Calls/... (may be interesting, may be showstoppers !)",filename)
          tofile("-" * 80,filename)
          cis=cinstructs.split('\n')
          for cielem in cis:
            tofile(cielem,filename)
        imm.log("After filtering and mutating, %d 'good' gadgets were left over" % (nrgood))
        imm.updateLog()
        thistimestamp=datetime.datetime.now().strftime("%a %Y/%m/%d %I:%M:%S %p")
        tofile("\nROP Gadget creating process complete at " + thistimestamp,progressfile)
        tofile(str(nrgood)+" gadgets created.",progressfile)
        return "Search complete, %d gadgets generated, check %s" % (nrgood,filename)

    if args[0] == "ropcall":
        imm.log("------------------------------------------------")
        imm.log("Searching for interesting calls to ROP bypass")
        imm.log("functions in loaded modules")
        imm.log("------------------------------------------------")
        filename="ropcall.txt"
        resetfile(filename)
        writemodinfo(filename)
        extrafilter=" "
        searchcall=[]
        mbase=0
        searchcall.append("WinExec")
        searchcall.append("VirtualProtect")
        searchcall.append("VirtualAlloc")
        searchcall.append("SetProcessDEPPolicy")
        searchcall.append("HeapCreate")
        searchcall.append("SetInformationProcess")
        searchcall.append("WriteProcessMemory")
        searchcall.append("memcpy")
        searchcall.append("memmove")
        searchcall.append("strncpy")
        searchcall.append("wsa")
        aslrfilt="ASLR: ** NO"
        fixupfilt="FIXUP: ** NO"
        isfixup=0
        if len(g_modules)==0:
           moduleinfo()
        imm.updateLog()
        #get correct module name
        isaslr=0
        mfound=0
        if modulefilter <> "":
          for mname in g_modules:
              mnamentry=mname.split('\t')
              if mnamentry[0].lower().startswith(modulefilter.lower()):
                  mfound=1
                  modulefilter=mnamentry[0].lower()
                  mbase=int(mnamentry[2])
                  isaslr=int(mnamentry[6])
                  isfixup=int(mnamentry[8])
        if modulefilter <> "" and mbase > 0:
            imm.log("[+] Module filter set to '%s', at baseaddress 0x%s" % (modulefilter,tohex(mbase)))
            tofile(" [+] Module filter set to '" + modulefilter+"'",filename)
            aslrfilt=" "
            fixupfilt=" "
            if isaslr==1:
                imm.log("    ! Module is aslr aware - you'd better start looking for memory leaks now :-)")
                tofile(" [+] Warning : module is ASLR enabled !",filename)
            else:
                imm.log("    Module is not aslr aware")
        else:
            imm.log("[+] No module filter set ")
        imm.updateLog()
        #start searching for calls
        addys=[]
        imm.log("Finding CALL instructions...")
        imm.updateLog()
        calltypes=[]
        calltypes.append("\xff\x15")
        totalcalls=0
        for calltype in calltypes:
           addys+=imm.search(calltype)
           totalcalls=totalcalls+len(addys)
        imm.log("Total number of calls found (in all modules) : %d" % len(addys))
        imm.log("Filtering calls... please wait")
        imm.updateLog()
        for callentry in addys:
            callproceed=0
            module = imm.findModule(callentry)
            if not module:
                module = "none"
            else:
                module = module[0].lower()
            modaslr=getmoduleprop(module,"aslr")
            modfixup=getmoduleprop(module,"fixup")
            if (nonull==0) or (nonull==1 and addressspec(tohex(callentry)).upper().find("NULL BYTE") == -1):
              if modaslr=="0" and modfixup=="0":
                if modulefilter <> "":
                    if module.lower().find(modulefilter.lower()) > -1:
                        callproceed=1
                else:
                    callproceed=1
                if callproceed==1 and addressinfo(callentry).find("EXECUTE") > -1:
                    hexaddr=tohex(callentry)
                    op = imm.Disasm( callentry )
                    opstring=op.getDisasm()
                    for callfunc in searchcall:
                        if opstring.lower().find(callfunc.lower().lstrip().rstrip()) > -1:
                           tofile("["+module+"]  0x" + tohex(callentry)+" : " + opstring+" | ",filename,callentry)
                           nrfound+=1
        imm.log("Search complete, %d possibly interesting calls found" % nrfound)
        return "Search complete, %d possibly interesting calls found" % nrfound


    if args[0] == "jrop":
      imm.log("--------------------------------------------------------------")
      imm.log("Search for jumpboards to ROP chain at ESP ")
      imm.log("Searching in non aslr modules... please wait")
      imm.log("--------------------------------------------------------------")
      filename="jrop.txt"
      resetfile(filename)
      writemodinfo(filename)
      opcodej=[]
      opcodej.append("call dword [esp]")
      opcodej.append("call dword [esp+0x04]")
      opcodej.append("call dword [esp+0x08]")
      opcodej.append("call dword [esp+0x0c]")
      opcodej.append("pop eax\njmp eax")
      opcodej.append("pop eax\ncall eax")
      opcodej.append("pop ebx\njmp ebx")
      opcodej.append("pop ebx\ncall ebx")
      opcodej.append("pop ecx\njmp ecx")
      opcodej.append("pop ecx\ncall ecx")
      opcodej.append("pop edx\njmp ecx")
      opcodej.append("pop edx\ncall edx")
      opcodej.append("pop esi\njmp esi")
      opcodej.append("pop esi\ncall esi")
      opcodej.append("pop edi\njmp edi")
      opcodej.append("pop edi\ncall edi")
      opcodej.append("pop ebp\njmp ebp")
      opcodej.append("pop ebp\ncall ebp")
      allregs=["eax","ebx","ecx","edx","esi","edi","ebp"]
      for reg in allregs:
          opcodej.append("lea "+reg+",[esp]\njmp "+reg)
          opcodej.append("lea "+reg+",[esp]\ncall "+reg)
          for reg2 in allregs:
             opcodej.append("pop "+reg+"\nxchg "+reg+","+reg2+"\njmp "+reg2)
             opcodej.append("pop "+reg+"\nxchg "+reg+","+reg2+"\ncall "+reg2)
             opcodej.append("pop "+reg+"\nxchg "+reg2+","+reg+"\njmp "+reg2)
      if len(g_modules)==0:
            moduleinfo()
      mbase=0
      if modulefilter <> "":
        for mname in g_modules:
            mnamentry=mname.split('\t')
            if mnamentry[0].lower().startswith(modulefilter.lower()):
                modulefilter=mnamentry[0].lower()
                mbase=int(mnamentry[2])
                imm.log("Module filter active : %s (baseaddress 0x%s)" % (modulefilter,tohex(mbase)))
      nrfound=0
      for op in opcodej:
        imm.log("Searching for %s " % op)
        addys=[]
        addys=imm.search(imm.assemble(op))
        imm.log("  Pointers found : %d " % len(addys))
        for ad1 in addys:
            modproceed=0
            module = imm.findModule(ad1)
            if not module:
                module = "none"
            else:
                module = module[0].lower()
            modaslr=getmoduleprop(module,"aslr")
            modfixup=getmoduleprop(module,"fixup")
            if (noos==0) or (noos==1 and isosmodule(module)==0):
               aspec=addressspec(tohex(ad1)).upper()
               if (nonull==0) or (nonull==1 and aspec.find("NULL") == -1):
                 if modaslr=="0" and modfixup=="0":
                   if modulefilter <> "":
                     if module.lower().find(modulefilter.lower()) > -1:
                        modproceed=1
                   else:
                        modproceed=1
            if modproceed==1 and addressinfo(ad1).find("EXECUTE") > -1:
                    hexaddr=tohex(ad1)
                    tofile("["+module+"]  0x" + tohex(ad1)+" : " + op+" | ",filename,ad1)
                    nrfound+=1
            imm.updateLog()
      imm.log("Search complete, found %d usable addresses" % nrfound)
      imm.log("Output written to "+filename)
      return "Search complete, %d pointers found" % nrfound

    if args[0] == "modules":
        writemodinfo("")

    if args[0] == "functions":
      imm.log("--------------------------------------------------------------")
      imm.log("Listing all functions in loaded modules")
      imm.log("--------------------------------------------------------------")
      filename="functions.txt"
      resetfile(filename)
      writemodinfo(filename)
      tofile("Function pointers :",filename)
      tofile("-------------------",filename)
      allowos=0
      dohook=0
      modname=""
      if len(args) > 1:
        starg=1
        while starg < len(args):
           if (args[starg].upper() == "ALL"):
             allowos=1
           if (args[starg].upper() == "BP"):
             dohook=1
           starg=starg+1
      if (allowos==0):
          imm.log(" [+] Not showing functions from dll's in windows folder")
      else:
          imm.log(" [+] Showing functions from all loaded modules")
      if (dohook==0):
          imm.log(" [+] No going to set breakpoints")
      else:
          imm.log(" [+] Enabling breakpoints on all functions")
      if len(g_modules)==0:
           moduleinfo()
      if modulefilter <> "":
          imm.log(" [+] Only showing functions from module %s" % modulefilter)
      imm.updateLog()
      nrfuncs=0
      calltypes=[]
      fprol=[]
      addys=[]
      foundfuncs=[]
      imm.updateLog()
      for mname in g_modules:
        mnamentry=mname.split('\t')
        modname=mnamentry[0].lower()
        mbase=int(mnamentry[2])
        mloc=mnamentry[1]
        dosearch=1
        if allowos==0 and isosmodule(modname) == 1:
                dosearch=0
        if modulefilter <> "" and modname.lower().find(modulefilter.lower()) == -1:
                dosearch=0
        imm.updateLog()
        if dosearch==1:
           allfunctions = imm.getAllFunctions(mbase)
           imm.log("Number of functions found in %s : %d (pass 1)" % (modname,len(allfunctions)))
           for func in allfunctions:
              thisfunction=imm.getFunction(func)
              funcaddress=thisfunction.getStart()
              funcname=thisfunction.getName()
              if funcaddress > 0:
                try:
                    itemf = foundfuncs.index(funcaddress)
                    #imm.log("Skipping duplicate pointer %s (index %d)" % (tohex(funcaddress),itemf))
                except ValueError:
                    funcend=getRet(imm,funcaddress)
                    if funcend > 0:
                      imm.log(" * Adding new function at 0x%s (RET at 0x%s) to list" % (tohex(funcaddress),tohex(funcend)))
                      foundfuncs.append(str(funcaddress)+" "+str(funcend))
                      nrfuncs=nrfuncs+1
                    else:
                      imm.log(" * Could not find end of function at 0x%s - pointer skipped" % tohex(funcaddress))
           #also look for function prologues in this module
           prologue="PUSH EBP\n MOV EBP,ESP\n"
           thissearch=prologue.decode('string_escape')
           addys=imm.searchCommandsOnModule(mbase,thissearch)
           #get function begin for each of those addys
           for prol in addys:
                #funcbegin=imm.getFunctionBegin(prol[0])
                #if funcbegin==0:
                funcbegin=prol[0]
                try:
                  itemf = foundfuncs.index(funcbegin)
                  #imm.log("Skipping duplicate pointer %s (index %d)" % (tohex(funcbegin),itemf))
                except ValueError:
                    funcend=getRet(imm,funcbegin)
                    if funcend > 0:
                      imm.log(" * Adding new function at 0x%s (RET at 0x%s) to list" % (tohex(funcbegin),tohex(funcend)))
                      foundfuncs.append(str(funcbegin)+" "+str(funcend))
                      nrfuncs=nrfuncs+1
                    else:
                      imm.log(" * Could not find end of function at 0x%s - pointer skipped" % tohex(funcbegin))
           imm.log("Number of prologues found in %s : %d (pass 2)" % (modname,len(addys)))
           #finally look for calls into either the executable or non OS modules
           calls="CALL offset"
           nrcall=0
           addys=imm.searchCommandsOnModule(mbase,calls)
           for thiscall in addys:
                op = imm.Disasm( thiscall[0] )
                opstring=op.getDisasm()
                #filter out OS calls
                if opstring.upper().find("<") == -1:
                    if opstring.upper().find(".") > -1:
                      addressparts=opstring.split('.')
                      try:
                        targetfunc=addresstoint(addressparts[len(addressparts)-1])
                        #filter more OS calls
                        if isosmodule(addressparts[0])==0:
                          try:
                            itemf = foundfuncs.index(targetfunc)
                            #imm.log("   Skipping duplicate pointer %s (index %d)" % (tohex(targetfunc),itemf))
                          except ValueError:
                            addptr=1
                            if (allowos==0):
                                ainfo=addressinfo(targetfunc)
                                if isosmodule(ainfo)==0:
                                   addptr=0
                            if addptr==1:
                                  funcend=getRet(imm,targetfunc)
                                  if funcend > 0:
                                     imm.log(" * Adding new function at 0x%s (RET at 0x%s) to list" % (tohex(targetfunc),tohex(funcend)))
                                     foundfuncs.append(str(targetfunc)+" "+str(funcend))
                                     nrfuncs=nrfuncs+1
                                  else:
                                     imm.log(" * Could not find end of function at 0x%s - pointer skipped" % tohex(targetfunc))
                                  nrcall=nrcall+1
                      except:
                          pass
           imm.log("Number of functions found in %s : %d (pass 3)" % (modname,nrcall))
      imm.log("Total number of unique functions found : %d" % len(foundfuncs))
      imm.log("Dumping function pointers to file")
      imm.updateLog()
      for thisptr in foundfuncs:
          tptr=str(thisptr).split(' ')
          fsize=int(tptr[1])-int(tptr[0])
          tofile("sub_"+tohex(int(tptr[0]))+"     .text "+tohex(int(tptr[0]))+" "+tohex(fsize),filename,int(tptr[0]))
          if (dohook==1):
             imm.setBreakpoint(int(tptr[0],16))
      imm.log("Done.")
      imm.updateLog()
      return "%i functions found." % len(foundfuncs)

    if args[0] == "omelet":
        shellcodefile=""
        filename="omelet.txt"
        egg_size=123
        egg_tag="303077"
        if len(args) > 1:
          cnt=1
          while cnt < len(args):
            if args[cnt]=='-f':
                if cnt < (len(args)-1):
                    shellcodefile=args[cnt+1]
            if args[cnt]=='-s':
                if cnt < (len(args)-1):
                    egg_size=args[cnt+1]
            if args[cnt]=='-t':
                if cnt < (len(args)-1):
                    egg_tag=args[cnt+1]
            cnt=cnt+1
        #egg tag should be 6 chars
        if len(egg_tag) != 6:
            imm.log("Tag should be 6 characters !",highlight=1)
            return "Error - check input"
        #egg size
        if IsNumber(egg_size):
            if int(egg_size) <= 1 or int(egg_size) > 123:
                imm.log("Invalid egg block size value. Value must be > 0 and <= 123")
                return "Error - check input"
        else:
            imm.log("Maximum egg block size value is not a number")
            return "Error - check input"
        #filename
        if os.path.isfile(shellcodefile):
            resetfile(filename)
            imm.log("Reading file %s..." % shellcodefile)
            srcdata=[]
            srcfile = open(shellcodefile,"rb")
            content = srcfile.readlines()
            srcfile.close()
            for eachLine in content:
              srcdata += eachLine
            imm.log("[+] Read %d bytes from file" % len(srcdata))
            #calculate number of eggs
            egg_size=int(egg_size)
            nr_eggs=len(srcdata) / egg_size
            delta=nr_eggs * egg_size
            if delta < len(srcdata):
                nr_eggs=nr_eggs+1
            imm.log("[+] Number of eggs to be generated : %d" % nr_eggs)
            #first, create the omelet
            imm.log("[+] Generating omelet code...")
            omelet = "\xeb\x24\x54\x5f\x66\x81\xcf\xff\xff\x89\xfa\x31\xc0\xb0"
            omelet += binascii.unhexlify(tohexbyte(nr_eggs))
            omelet += "\x31\xf6\x66\xbe"
            omelet += binascii.unhexlify(tohexbyte(237-egg_size))
            omelet += "\xff\x4f\x46\x66\x81\xfe\xff\xff\x75\xf7\x48\x75\xee\x31\xdb\xb3"
            omelet += binascii.unhexlify(tohexbyte(nr_eggs+1) )
            omelet += "\xc3\xe8\xd7\xff\xff\xff\xeb\x04\x4a\x4a\x4a\x4a\x42\x52\x6a\x02"
            omelet += "\x58\xcd\x2e\x3c\x05\x5a\x74\xf4\xb8\x01"
            omelet += binascii.unhexlify(egg_tag)
            omelet += "\x01\xd8\x87\xfa"
            omelet += "\xaf\x87\xfa\x75\xe2\x89\xd6\x31\xc9\xb1"
            omelet += binascii.unhexlify(tohexbyte(egg_size))
            omelet += "\xf3\xa4\x4b\x80\xfb\x01\x75\xd4\xe8\xa4\xff\xff\xff\xff\xe7"
            imm.log("    Omelet size : %d bytes" % len(omelet))
            #write omelet to file
            cnt=0
            linecnt=0
            byteperline=16
            hexchar=""
            tofile("",filename)
            tofile("#corelanc0d3r's eggs-to-omelet hunter",filename)
            tofile("#" + str(len(omelet))+" bytes // http://www.corelan.be:8800",filename)
            tofile("my $omelet = ",filename)
            omeletstring=""
            while (cnt < len(omelet)):
                if len((hex(ord(omelet[cnt]))).replace('0x',''))==1:
                    hexchar= hexchar + "\\x" + hex(ord(omelet[cnt])).replace('0x', '0')
                else:
                    hexchar = hexchar + "\\x" + hex(ord(omelet[cnt])).replace('0x', '')
                linecnt=linecnt+1
                cnt=cnt+1
                if linecnt==(byteperline-1) or (cnt == len(omelet)):
                    if cnt == len(omelet):
                       tofile("\""+hexchar+"\";",filename)
                       hexchar=""
                    else:
                      if linecnt==(byteperline-1):
                         tofile("\""+hexchar+ "\" .",filename)
                         hexchar=""
                    linecnt=0
            #adding nops if necessary
            imm.log("    Original shellcode size : %d" % len(srcdata))
            nops="A" * ((nr_eggs * egg_size) - len(srcdata))
            for nopbyte in nops:
                srcdata.append(nopbyte)
            shell_size=len(srcdata)
            imm.log("    Total shellcode size, %d byte aligned : %d" % (egg_size,shell_size))
            imm.log("[+] Generating eggs...")
            eggcnt=nr_eggs+2
            startcode=0
            cnt=0
            eggbytes=0
            eggsdone=0
            source=""
            hexchar=""
            thisegg=""
            while (cnt < shell_size):
              while (eggbytes < egg_size) and (cnt < shell_size):
                try:
                  if len((hex(ord(srcdata[cnt]))).replace('0x',''))==1:
                    hexchar=hex(ord(srcdata[cnt])).replace('0x', '0')
                  else:
                    hexchar = hex(ord(srcdata[cnt])).replace('0x', '')
                  thisegg += srcdata[cnt]
                  cnt=cnt+1
                  eggbytes=eggbytes+1
                except:
                  imm.log("Unable to process byte %d " % cnt)
                  cnt=cnt+1
                  eggbytes=eggbytes+1
                  pass
                if eggbytes == egg_size:
                    eggsdone=eggsdone+1
                    thistag = "\\x"+tohexbyte(eggcnt)+"\\x"+egg_tag[0]+egg_tag[1]+"\\x"+egg_tag[2]+egg_tag[3]+"\\x" + egg_tag[4]+egg_tag[5]
                    tagbyte=binascii.unhexlify(tohexbyte(eggcnt)+egg_tag)
                    thisegg = tagbyte + thisegg
                    imm.log("  - Created egg %d, tag %s, len %d " % (eggsdone,thistag,len(thisegg)))
                    #write this one to file
                    tofile("",filename)
                    tofile("#egg " + str(eggsdone)+" : ",filename)
                    tofile("my $egg" + str(eggsdone)+" = ",filename)
                    ecnt=0
                    linecnt=0
                    byteperline=16
                    hexchar=""
                    while (ecnt < len(thisegg)):
                        if len((hex(ord(thisegg[ecnt]))).replace('0x',''))==1:
                           hexchar= hexchar + "\\x" + hex(ord(thisegg[ecnt])).replace('0x', '0')
                        else:
                           hexchar = hexchar + "\\x" + hex(ord(thisegg[ecnt])).replace('0x', '')
                        linecnt=linecnt+1
                        ecnt=ecnt+1
                        if linecnt==(byteperline-1) or (ecnt == len(thisegg)):
                            if ecnt == len(thisegg):
                               tofile("\""+hexchar+"\";",filename)
                               hexchar=""
                            else:
                               if linecnt==(byteperline-1):
                                   tofile("\""+hexchar+ "\" .",filename)
                                   hexchar=""
                            linecnt=0
                    eggcnt=eggcnt-1
                    eggbytes=0
                    thisegg=""
            imm.log(" [+] Done - check omelet.txt")
        else:
            imm.log("Could not read shellcode file",highlight=1)
            return "Error"
        return "Done - check omelet.txt"

    if args[0] == "filecompare":
        filename="filecompare.txt"
        allfiles=[]
        rawfilenames=""
        refpointer=""
        comppointers=0
        if len(args) > 1:
          cnt=1
          paramf=0
          while cnt < len(args):
            if args[cnt]=='-f' or paramf==1:
                #read all filenames
                paramf=1
                if cnt < (len(args)-1):
                    rawfilenames=rawfilenames + " " +args[cnt+1].lower()
            cnt=cnt+1
          rawfilenames=rawfilenames.replace('"',"")
          allfiles = rawfilenames.split(',')
        imm.log("Number of files to be examined : %d : " % len(allfiles))
        #check if file exists
        fcnt=0
        filesok=0
        while fcnt < len(allfiles):
            allfiles[fcnt]=allfiles[fcnt].strip()
            if os.path.exists(allfiles[fcnt]):
                imm.log(" - %s" % allfiles[fcnt])
                filesok=filesok+1
            else:
                imm.log("** %s : Does not exist !" % allfiles[fcnt])
            fcnt=fcnt+1
        if filesok > 1:
            resetfile(filename)
            tofile("Source files :",filename)
            fcnt=0
            while fcnt < len(allfiles):
                tofile(" - " + allfiles[fcnt],filename)
                fcnt=fcnt+1
            tofile("",filename)
            tofile("Pointers found :",filename)
            tofile("----------------",filename)
            imm.log("Reading reference file %s " % allfiles[0])
            imm.updateLog()
            #open reference file and read all records that contain a pointers
            reffile = open(allfiles[0],"rb")
            refcontent = reffile.readlines()
            reffile.close()
            #read all other files into a big array
            targetfiles=[]
            filecnt=1
            imm.log("Reading other files...")
            imm.updateLog()
            while filecnt < len(allfiles):
                imm.log("   %s" % allfiles[filecnt])
                imm.updateLog()
                targetfiles.append([])
                tfile=open(allfiles[filecnt],"rb")
                tcontent = tfile.readlines()
                tfile.close()
                nrlines=0
                for myLine in tcontent:
                    targetfiles[filecnt-1].append(myLine)
                    nrlines=nrlines+1
                filecnt=filecnt+1
            totalptr=0
            imm.log("Starting compare operation, please wait...")
            imm.updateLog()
            for thisLine in refcontent:
                refpointer=""
                pointerfound=1  #pointer is in source file for sure
                #is this a pointer line ?
                if thisLine.lower().find("at 0x") > -1 or thisLine.lower().find("0x") == 0:
                    #yes, get pointer
                    pointerraw=[]
                    if thisLine.lower().find("at 0x") > -1:
                       pointerraw=thisLine.split(" at ")
                    if thisLine.lower().find("0x") == 0:
                       pointerraw.append("")
                       pointerraw.append(thisLine)
                    if len(pointerraw) > 1:
                        totalptr=totalptr+1
                        ptrparts=pointerraw[1].split(" ")
                        refpointer = ptrparts[0].strip().lower()
                        #try to find pointer in array of files
                        filecnt=0  #0 is actually the second file
                        while filecnt < len(allfiles)-1 :
                            foundinfile=0
                            for srcLine in targetfiles[filecnt]:
                                if srcLine.lower().find(refpointer) > -1:
                                    foundinfile=1
                            pointerfound=pointerfound+foundinfile
                            filecnt=filecnt+1
                        #search done
                        if pointerfound == len(allfiles):
                            imm.log(" -> Pointer %s found in %d files" % (refpointer,pointerfound))
                            tofile(refpointer + " :: " + thisLine.replace('\n','').replace('\r',''),filename)
                            comppointers=comppointers+1
                            imm.updateLog()
            imm.log("Total number of pointers queried : %d" % totalptr)
            imm.log("Number of matching pointers found : %d - check filecompare.txt for more info" % comppointers)
            return("Operation completed, " + str(comppointers) + " pointers found - check filecompare.txt")
        else:
           if filesok == 1:
              imm.log("** Only one file was found. You need at least 2 files to do a compare")
              return("Only one file found. You need at least 2 files to do a compare")
           else:
              imm.log("** No files could be found, operation aborted")
              return("No files could be found, check input")


    if (args[0] == "dump"):
        dodump(args)

    if(args[0] == "retslide"):
        filename="retslide.txt"
        imm.log("--------------------------")
        imm.log(" Searching for ret slides")
        imm.log("--------------------------")
        imm.updateLog()
        resetfile(filename)
        if len(g_modules)==0:
            moduleinfo()
        opcodej=[]
        ignorefixup=0
        maxretval = 32
        cnt=1
        while cnt < len(args):
            if args[cnt]=='-r':
                if cnt < (len(args)-1):
                    maxretval=int(args[cnt+1])
            cnt=cnt+1
        opcodej.append("RET")
        c1=2
        while c1 <= maxretval:
            opcodej.append("RET " + tohexbyte(c1)+"\n")
            c1=c1+2
        imm.updateLog()
        nrslides=0
        nrgood=0
        addys=[]
        #get all search results
        imm.log(" - Searching memory for slides, please wait...")
        scnt=1
        opnr=len(opcodej)
        for searchcmd in opcodej:
            imm.log("   Search sequence %d / %d" % (scnt,opnr))
            addys += imm.searchCommands(searchcmd.strip())
            scnt=scnt+1
            imm.updateLog()
        imm.log(" - Total number of ret pointers found in memory: %d " % len(addys))
        imm.log(" - Now filtering for pointers that could be used to slide")
        for ad1 in addys:
            ad1 = ad1[0]
            hexaddr = tohex(ad1)
            modulename = getmodnamefromptr(ad1)
            b1 = hexaddr[0] + hexaddr[1]
            b2 = hexaddr[2] + hexaddr[3]
            b3 = hexaddr[4] + hexaddr[5]
            b4 = hexaddr[6] + hexaddr[7]
            if b1 == b2 and b2 == b3 and b3 == b4:
                imm.log("Full ret slide pointer found at 0x%s" % hexaddr)
                op = imm.Disasm( ad1 )
                opstring=op.getDisasm()
                tofile("0x" + hexaddr + " : FULL - " + opstring + " [" + modulename+"]",filename,ad1)
                imm.updateLog()
                nrslides=nrslides+1
                nrgood=nrgood+1
            else:
                if b1==b2 and b2==b3 and addresstoint(b4) >= addresstoint(b3):
                    imm.log("Close full ret slide pointer found at 0x%s" % hexaddr)
                    op = imm.Disasm( ad1 )
                    opstring=op.getDisasm()
                    tofile("0x" + hexaddr + " : CLOSE - " + opstring + " [" + modulename+"]",filename,ad1)
                    imm.updateLog()
                    nrslides=nrslides+1
                else:
                  if b1==b2 and b3==b4:
                    imm.log("Half ret slide pointer found at 0x%s" % hexaddr)
                    op = imm.Disasm( ad1 )
                    opstring=op.getDisasm()
                    tofile("0x" + hexaddr + " : HALF - " + opstring + " [" + modulename+"]",filename,ad1)
                    imm.updateLog()
                    nrslides=nrslides+1
        imm.log("Number of slide pointers found : %d (out of which %d are full slides)" % (nrslides,nrgood))
        return "Done"