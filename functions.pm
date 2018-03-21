#
#
# (c) SkyboxSecurity 2015
#
# Author: Scott Bianco
#
#	General purpose PM
#	Contains functions for formating cli output and ip address calculations
#
#	Version 2.0	- 10/20/2014
#	Version 2.1	- 10/29/2014	enhanced the __test_sock function
#	Version 2.2	- 01/13/2015	removed ip functions into their own pm
#					removed Net::IP and Network::IPv4 

#
# Dependencies:	
#
#	Required:	Switch			: as the name implies - use the "Switch" control function
#			Digest::MD5		: for hashing values for unique index 
#			Text::CSV_XS		: for reading and manipulating CSV files 
#			Socket			: for the ssh socket functions
# 
use strict;
use Switch;
use Socket;
use Text::CSV_XS qw (csv);
#use Data::Dumper;
#use Digest::MD5 qw(md5 md5_hex);	# added 11/9/2012 for hashing

use constant {
	CRITICAL	=> 0,
	ERROR		=> 1,
	WARNING		=> 2,
	NOTICE		=> 3,
	INFO		=> 4,
	DEBUG		=> 5
	};

use constant KILL => 1;

my @log_msg	= ();	# array to hold log messages
my @log_error	= ();	# array to hold error log messages

my $DEBUG_FLAG;
my $HOSTNAME;
my $ERROR_CNT	= 0;
my $WARN_CNT	= 0;
my @ssh_pids	= ();

sub _print_header {
        ########################################
        #
        #       name            : _print_header
        #       purpose         : write a consistant header message to stdout
        #                         
        #
        #       parameters      : version and copywrite
        #       return          : void
        #
        ########################################

	my $V		= $_[0];
	my $CW		= $_[1];
	my $THISHOST = `hostname -s`;
	chomp($THISHOST);

	my $TS = &_get_ts(0,undef);

	my $MSGSTR = "
$V
$CW
[STARTED]: $TS ON SERVER: $THISHOST
=================================================================

";

	print $MSGSTR;
	push (@log_msg,$MSGSTR);
	push (@log_error,$MSGSTR);

	return;

}

sub show {
	#########################################
	#
	# 	name		: show
	# 	purpose		: write to stdout at various levels
	# 			  if debug, test to see if the flag is set prior to output
	#
	# 	parameters	: message 	- string message to write out
	#			  level		- message severity level from 0 (critical) to 5 (debug)
	#
	#	return		: void
	#
	#########################################

	my ($message,$level,$killit) = @_;
	chomp $message;
	
	if (! defined($level)) { $level = 4; }	# set the default - info
	
	#	calculate timestamp
	my $TS = &_get_ts(0);

	my @level = ("[CRITICAL]:\t","[ERROR]:\t","[WARNING]:\t","[NOTICE]:\t","[INFO]:\t","[DEBUG]:\t");

	# 	output to STDOUT for now
	my $MSGSTR 	= "$TS ";
	$MSGSTR 	.= "{$HOSTNAME}: " if ($HOSTNAME);
	$MSGSTR 	.= $level[$level]." $message\n";

	push (@log_msg,$MSGSTR);

	if ($level == 0||$level == 1||$level == 2) {
		push (@log_error,$MSGSTR);
	}

	$ERROR_CNT++	if ($level == 0||$level == 1);
	$WARN_CNT++	if ($level == 2);

	print $MSGSTR	unless (($level == 5) && (! $DEBUG_FLAG == 1));
	if ($killit)	{ exit 1; }

}

sub write_log {
	#########################################
	#
	# 	name		: write_log
	# 	purpose		: write the accumlative array for messages (both run and error)
	# 			  to a log file if the parameter is populated
	#
	# 	parameters	: log_file	- standard runtime log filename
	#			  error_file	- error logfile to write just error messages to
	#
	#	return		: void
	#
	#########################################

	my $log_file 	= shift;
	my $error_file	= shift;

	if ($log_file) {
		unless (open (FH,">>",$log_file)) { &show ("Error writing logfile !!!",ERROR); return; }
		foreach my $l (@log_msg) {
			print FH $l;
		}
		close FH;
	}

	if ($error_file) {
		unless (open (FH,">>",$error_file)) { &show ("Error writing error log !!!",ERROR); return; }
		foreach my $l (@log_error) {
			print FH $l;
		}
		close FH;
	}

	return;

}

sub _get_error_cnt {
	return $ERROR_CNT;
}

sub _get_warning_cnt {
	return $WARN_CNT;
}

sub _set_debug_flag {
	########################################
	#
	# 	name		: _set_debug_flag
	# 	purpose		: set the local debug var so that it can be used in show
	#				  without passing it in every time
	#
	#	parameters	: debug (0 or 1)
	#	return		: void
	#
	########################################

	$DEBUG_FLAG = $_[0];	#expect 0|1

	&show ("Debug flag set",5);

}

sub _set_hostname {
        ########################################
        #
        #       name            : _set_hostname
        #       purpose         : set the internal hostname variable for show messages
        #                         
        #
        #       parameters      : hostname (if empty, use system hostname from localhost
        #       return          : void
        #
        ########################################

	$HOSTNAME = $_[0];
	$HOSTNAME = `hostname -s` unless ($HOSTNAME);
	chomp($HOSTNAME);

	&show ("Set logging hostname: [$HOSTNAME]",5);

}


sub _get_ts {
	#########################################
	#
	# function		: _get_ts
	# purpose		: return a formated timestamp
	#
	# parameters	: 	time_format - type of format to return
	#			default - yyyy-mm-dd-hh-mm-ss
	#		        1 	- mm/dd/yyyy hh:mm am|pm
	#		        2	- yyyymmdd
	#		        3	- mmddyyyy
	#			task	- yyyy-mm-dd
	#					
	#			unix epoch - ts to convert
	#			default - now using time()
	#			can be any unix epoch
	#
	#
	# return		: string - requested format of now()
	#
	#########################################

	my $time_format = $_[0];
	my $unix_epoch	= (defined($_[1])) ? $_[1] : time;

	my ($year, $month, $day,$hr,$min,$sec) = (localtime($unix_epoch))[5,4,3,2,1,0];
	my $YR=$year+1900;
	my $MN=$month+1;
	my $AM_PM = "AM";
	my $hr_12 = 0;
	my $TS;

	#
	# get AM/PM and adjust hour
	#
	if ($hr > 12) {
		$hr_12	= $hr - 12;
		$AM_PM 	= "PM";
	}
	
	#
	#	switch based on requested format
	#
	switch ($time_format) {

		#	mm/dd/yyyy hh:mm am|pm
		case 1 {
			$TS = sprintf("%02d/%02d/%04d %02d:%02d %02s",$MN,$day,$YR,$hr_12,$min,$AM_PM);
		}	

		#	yyyymmdd
		case 2 {
			$TS = sprintf("%04d%02d%02d",$YR,$MN,$day);
		}
		
		#	mmddyyyy
		case 3 {
			$TS = sprintf("%02d%02d%04d",$MN,$day,$YR);
		}
		
		#	yyyy-mm-dd
		case "task" {
			$TS = sprintf("%04d-%02d-%02d",$YR,$MN,$day);
		}

		# 	yyyy-mm-dd-hh-mm-ss
		else {
			$TS = sprintf("%4d-%02d-%02d-%02d-%02d-%02d",$YR,$MN,$day,$hr,$min,$sec);
		}

	}	# end switch time_format #

	return $TS;

}

sub _get_hash {
	#########################################
	#
	# function		: _get_hash
	#
	# purpose		: return a unique hash to identify the accompying array
	#
	# parameters	: line	- string value containing line to be hashed
	#
	# return		: string - hash value
	#
	#########################################

	my @tobehashed	 	= @_;
	my $RET 			= md5_hex(@tobehashed);

	return $RET;

}

################################
#
#	return current time in skybox format
#
sub _get_sbv_time {

	#my $sbv_time = 1356228923;	# sometime on 1/3/2014 2:50 pm EST

	# or	(i think time_key is off)
	#my $sbv_time = time - $time_key;
	my $sbv_time = time * 1000 / 1024;

	return $sbv_time;

}

sub _open_ssh_tunnel {
	#########################################
	#
	# function		: _open_ssh_tunnel
	#
	# purpose		: fork an ssh process which opens a local listener to the remote host
	#
	# parameters		: remote host to open tunnel to
	#
	# return		: port used as local listener or default mysql port if no host provided
	# 			  this allows the function to be used regardless of whether a remote tunnel is needed
	# 			  if the remote host is empty, the call to open a db connection will be performed agaist the localhost
	#
	#########################################


	my $dst_host	= shift || return 3306;		# return default mysql port if no dst host provided
	my $src_port	= 0;
	
	# remote host defined, open tunnel and return source port
	
	my $sock	= 13306;
	my $sock_max	= 13325;
	my $b_found_sock = 0;

	until ($sock > $sock_max) {
		$b_found_sock	= &__test_sock($sock);
		last if ($b_found_sock);
		$sock++;
	}

	if ($b_found_sock) {

		$src_port = $sock;
		&show ("Opening ssh tunnel to [$dst_host] - Forwarding source port to DB: [$src_port]",DEBUG);

		my $pid	= fork();
		if ($pid == 0) {

			#&show ("in child process dossh - PID: $pid $$",DEBUG);
			my $constr = "ssh -N -q -l skyboxview -L $src_port:127.0.0.1:3306 $dst_host";
			&show ("Executing: [$constr]",DEBUG);
			exec ($constr);

		} elsif (defined($pid)) {

			&show ("In parent process - child pid: [$pid]",DEBUG);
			push(@ssh_pids,$pid);
			sleep 1;

		} else {

			&show ("Fork failed for $dst_host",CRITICAL,1);

		}

	} else {
		&show ("Could not find an open port to create ssh tunnel [13306 - $sock_max] !!! ABORTING !!!",CRITICAL,1);
	}
	
	return $src_port;

}

sub __test_sock {
	#########################################
	#
	# function		: __test_sock
	#
	# purpose		: detect if a local port is already in use
	#
	# parameters		: port to check
	#
	# return		: 0 if port unavailable (already in use)
	# 			  1 if port available	(not in use)
	#
	#########################################

	
	my $RET		= 0;
	my $port 	= shift || return $RET;		# return 0 if no port passed in

	my $host 	= 'localhost';			# always test localhost
	my $timeout 	= 5;				

	my $proto 	= getprotobyname('tcp');
	my $iaddr 	= inet_aton($host);
	my $paddr 	= sockaddr_in($port, $iaddr);

	socket(SOCKET, PF_INET, SOCK_STREAM, $proto) || &show("Problem creating socket for port test: [$!]",ERROR);
    
	eval {
		local $SIG{ALRM} = sub { &show ("Socket timout reached !!!",WARNING); };
		alarm($timeout);
		connect(SOCKET, $paddr) || (alarm(0) && die);	# just dies in eval if socket is open (connect returns with 0)
	};
    
	if ($@) {
		# port available
		close SOCKET || &show ("Problem closing socket: [$!]",ERROR);
		&show ("Port is open and available: [$port]",DEBUG);
		$RET = 1;
	} else {
		# port unavailable
		close SOCKET || &show ("Problem closing socket: [$!]",ERROR);
		&show ("Port is NOT available: [$port] !!!",DEBUG);
		$RET = 0;
	}

	return $RET;

}

sub _clean_pids {
	#########################################
	#
	# function		: _clean_pids
	#
	# purpose		: shut down open ssh tunnels created by open_tunnel
	#
	# parameters		: none
	#
	# return		: void
	#
	#########################################


	foreach my $pid (@ssh_pids) {
		
		&show ("Cleaning up ssh tunnel with pid: [$pid]",DEBUG);
		$pid	= `kill -9 $pid 2>&1 > /dev/null`;

	}

	return;

}

sub _read_csv {
	#########################################
	#
	# function		: _read_csv
	#
	# purpose		: open and read a CSV file; put contents into nested array
	#
	# parameters		: input file
	# 			: skip_header (0 or 1) (optional)
	#
	# return		: nested array of parsed csv
	#
	#########################################

	my $input_csv	= shift || return 0;
	my $skip_header = shift || 0;		# will skip line 1 (TODO: change to auto detect or add method)
	my @input_table = ();

	#
	#	get a handle on csv file
	#
	&show ("Parsing: [$input_csv]",DEBUG);
	
	##########
	# old way but works on JPMC
	my $csv	= Text::CSV_XS->new();
	open (my $fh,"<:encoding(utf8)",$input_csv) or &show("Could not open input file: [$input_csv] !!!",CRITICAL,KILL);

	while (my $row = $csv->getline ($fh)) {
     		push @input_table, $row;
     	}
 	close $fh;

	###########
	# new way does not work on older csv_xs module
	#my $csv = csv ( in => $input_csv);
	#@input_table = csv ( in => $input_csv);
	#@input_table = @$csv;
	#
	
	splice (@input_table,0,1)	if $skip_header;	# skip first line if optioned

	&show ("CSV file opened for reading",DEBUG);

	return @input_table;

}


1;
