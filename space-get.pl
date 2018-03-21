#!/usr/bin/perl
#
#
# (c) SkyboxSecurity 2015
#
# Name		: space-get.pl
# Date		: June 24, 2015
# Version	: V20150624_00001
# Author	: Scott Bianco
#
# Version	: V20150706_00001
# 		  07/06/2015	SVB
# 		  Added handling of http response code 204: no content
# 		  this code is returned by space when no config files have been stored in the associated domain
#
# 		: V20150714_00001
# 		  07/14/2015	SVB
# 		  -d | --device-api
# 		  Added support for pulling live configs via the device API
# 		  This requires device read permissions on the service account
# 		  (space role -> device management -> device configuration -> view active configuration)
# 		  The use of this API retrieves the device configuration with inheritance, however it is in XML format
# 		  and needs to be converted to heirarichal using the converter app "junos-convert.pl"
#
#		: V20150722_00001
#		  07/22/2015	SVB
#		  -r | --replace-hostname mode
#		  Added support for pulling basic configs using the first method of calling the configuration API,
#		  which gets stored versions of the configs and gets them in heiarachal format (what skybox supports),
#		  however without inheritance, which has the byproduct of causing HA cluster members to merge. 
#		  This version has support for -r mode, which will replace the hostname in the config (groups stanza)
#		  with the hostname obtained from space. This causes the devices NOT to merge, so that each cluster
#		  member comes in seperately.
#
# Dependencies:	Associated perl modules		
#						functions.pm	: logging and ip address methods
#						REST::Client	: restful API library
#						MIME::Base64	: used for basic auth
#						XML::Simple	: parse xml return strings from space
#						Time::ParseDate	: for checking config timestamps against filter
#
#

use strict;
use warnings;

use lib "/opt/LIBS";
use functions;

#####
# libraries for RESTFul APIs
use REST::Client;
use MIME::Base64;
use XML::Simple qw(:strict);

#####
# standard libraries needed
use Getopt::Long qw(:config bundling_override passthrough);
use File::Basename;
use Time::ParseDate;
use Data::Dumper;

#####

#####
# script variables
my $VERSION	= "Junos Space Integration - Version: V20150722_00001";
my $COPYWRITE	= "(c) 2015 Skybox Security Inc. - (www.skyboxsecurity.com)";
&_print_header($VERSION,$COPYWRITE);

#####
# Globals
my $DEBUG		= 0;
my $RET_opt		= 0;
my $get_help		= 0;
my %configs		= ();
my $RET			= 0;

#####
# counters
my $cnt_configs		= 0;
my $cnt_devices		= 0;
my $cnt_inactive	= 0;
my $cnt_downloaded	= 0;
my $cnt_retrieve_error	= 0;
my $cnt_write_error	= 0;
my $cnt_error		= 0;
my $cnt_old		= 0;

#####
# parameters
my $space_server	= "";
my $space_user		= "";
my $space_pass		= "";
my $output_dir		= "";
my $use_dev_type	= 0;
my $config_age		= 0;
my $use_device_api	= 0;
my $hostname_fix	= 0;

#####
# parse parameters
$RET_opt	= GetOptions	
			(	"v|verbose"		=>	\$DEBUG,
				"h|help"		=>	\$get_help,
				"s|space-server=s"	=>	\$space_server,
				"u|space-user=s"	=>	\$space_user,
				"p|space-pass=s"	=>	\$space_pass,
				"o|output-directory=s"	=>	\$output_dir,
				"t|dev-type-subdir"	=>	\$use_dev_type,
				"a|age=i"		=>	\$config_age,
				"d|device-api"		=>	\$use_device_api,
				"r|replace-hostname"	=>	\$hostname_fix,
			);

#####
# error check input
unless (($space_server)&&($space_user)&&($space_pass))	{ &usage; }
unless (($output_dir)&&( -r $output_dir ))		{ show ("Output directory is not valid: [$output_dir]",CRITICAL,1); }
if ($get_help)		{ &usage; }

show ("Using output directory: [$output_dir]");
show ("Will create subdirectories based on device family [-t option]")	if ($use_dev_type);

if ($config_age) {
	show ("Filter configuration date: [$config_age] days ago or newer");
	$config_age	= time() - ($config_age * 3600 * 24);

}

#####
# main

#
#	Set script wide parameters
#
&_set_debug_flag($DEBUG);

#
#	determine the method of pulling configs
#	either origonal method of using stored configs
#	or newer (and better) method of pulling directly from devices using the device api
#
if ($use_device_api) {
	
	show ("Using API method to use space to pull configs live from device (rather than stored configs)");
	$RET = &get_device_configs;

} else {

	#
	#	connect to space and enumerate configs
	#
	show ("Using API method to retieve stored configurations from space");
	unless (&get_configs) {
		
		#print Dumper %configs;
	
		#
		#	download configs
		#
		&download_configs;
	
	} else {

		#
		# problem getting configs
		#
		$RET = 1;
	
	}

}

#
#	feedback
#
&show ("Completed processing.");
if ($use_device_api)	{ &show ("Identified space devices: [$cnt_devices] | Retrieved: [$cnt_downloaded] | Inactive: [$cnt_inactive]"); }
else			{ &show ("Identified configs: [$cnt_configs] | Retrieved: [$cnt_downloaded] | Not retrieved due to date filter: [$cnt_old]"); }
&show ("Retrieval errors:   [$cnt_retrieve_error] | Write errors: [$cnt_write_error] | General errors: [$cnt_error]");

#
#	all done
#
exit $RET;

##################################################################################################

################################
################################

#
#	FUNCTIONS
#

################################
#
#       function:       get_device_configs
#
#       Purpose:        use the device api to retrieve a live running config from the device
#       		the config can only be retrieved using xml format using this mode
#       		write the config out once retrieved
#       
#
#	Parameters:     none
#
#
sub get_device_configs {

	show ("Retrieving configurations from space server: [$space_server] [$space_user]");
	
	my $api_configs		= "/api/space/device-management/devices";
	my $RET 		= 0;

	# needed to avoid server cert issues
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;


	my $space_client 	= REST::Client->new({ host => "$space_server" });
	my $h 			= { Authorization => 'Basic '.encode_base64("$space_user:$space_pass")};
	my $r 			= $space_client->GET($api_configs,$h);
	my $r_code		= $space_client->responseCode();
	my $r_content		= $space_client->responseContent();

	show ("Requested device enumeration: [$api_configs]",DEBUG);
	show ("Response Code: [$r_code]",DEBUG);

	#print Dumper $r;exit;

	if ($r_code == 200) {

		show ("Successful response");
		
		my $xs = XML::Simple->new();
		my $ref = $xs->XMLin($r_content, KeyAttr => { 'device' => 'key' }, ForceArray => [ 'device' ]);

		#print Dumper $ref;

		foreach my $dev_id (keys %{$ref->{'device'}}) {

			$cnt_devices++;

			my $dev_uri	= $ref->{'device'}->{$dev_id}->{'uri'};
			my $dev_name	= $ref->{'device'}->{$dev_id}->{'name'};
			my $dev_ip	= $ref->{'device'}->{$dev_id}->{'ipAddr'} || "";
			my $dev_family	= $ref->{'device'}->{$dev_id}->{'deviceFamily'};
			my $dev_status	= $ref->{'device'}->{$dev_id}->{'connectionStatus'};
			my $dev_sync	= $ref->{'device'}->{$dev_id}->{'managedStatus'};
			my $dev_platform= $ref->{'device'}->{$dev_id}->{'platform'};
			
			show ("Found device: [id $dev_id] [$dev_name $dev_ip] [$dev_family] status: [$dev_status] [$dev_sync]");

			if ($dev_status eq "up") {
				
				show ("[$dev_name] Device is up ... attempting to retrieve configuration from device");
	
				my $h 			= { Authorization => 'Basic '.encode_base64("$space_user:$space_pass") };
				
				my $api_dev_config	= "/api/space/device-management/devices/$dev_id/configurations/expanded";
				my $dr 			= $space_client->GET($api_dev_config,$h);
				my $dr_code		= $space_client->responseCode();
				my $dr_content		= $space_client->responseContent();

				show ("[$dev_name] Response code: [$dr_code]",DEBUG);

				if ($dr_code == 200) {
					
					#
					# derive filename to be written to output directory
					# use device id _ hostname _ configname (from space - ends in .conf)
					#
					my $local_file_name	= "$dev_id"."_"."$dev_name"."_"."$dev_ip".".xml";

					#
					# set path based - add device family if optioned
					#
					my $full_path		= $output_dir;
					$full_path 		.= "/".$dev_family	if ($use_dev_type);
					$full_path		.= "/".$local_file_name;
	
					my $dxs  = XML::Simple->new();
					my $dref = $dxs->XMLin($dr_content,KeyAttr => { 'expanded-configuration' => 'configuration'}, ForceArray => 1);
					my $tmpconf	= $dref->{'configuration'};

					if (open FH,">",$full_path) {
						show ("[$dev_name] Writing config file: [$full_path]");
						print FH $$tmpconf[0];
						$cnt_downloaded++;
					} else {
						show ("[$dev_name] Problem writing config file: [$full_path]",ERROR);
						$cnt_write_error++;
					}
					close FH;

				} else {

					show ("[$dev_name] Problem retrieving config | code: [$dr_code] [$dr_content]",ERROR);

				}

			} else {

				show ("[$dev_name] Not retrieving configuration due to status of: [$dev_status]",WARNING);
				$cnt_inactive++;

			}


			
			#show ("Storing config attibutes: [id $config_id] [$config_name] [v $config_ver] device: [id $dev_id] [$dev_name] [$dev_family]");
			#show ("Storing config uri: [$config_id] [$config_uri]",DEBUG);

			$cnt_configs++;

		}


	} else {

		show ("Problem enumerating devices - http response code: [$r_code: $r_content]",ERROR);
		$cnt_error++;
		$RET = 1;

	}

	return $RET;

}


################################
#
#       function:       get_configs
#
#       Purpose:        connect to space and build hash of all config attributes
#       		(not download - just enumerate)
#
#	Parameters:     none
#
#
sub get_configs {

	show ("Retrieving configurations from space server: [$space_server] [$space_user]");
	
	my $api_configs		= "/api/space/config-file-management/config-files";
	my $RET 		= 0;

	# needed to avoid server cert issues
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;


	my $space_client 	= REST::Client->new({ host => "$space_server" });
	my $h 			= { Authorization => 'Basic '.encode_base64("$space_user:$space_pass")};
	my $r 			= $space_client->GET($api_configs,$h);
	my $r_code		= $space_client->responseCode();
	my $r_content		= $space_client->responseContent();

	show ("Requested config enumeration: [$api_configs]",DEBUG);
	show ("Response Code: [$r_code]",DEBUG);

	if ($r_code == 200) {

		show ("Successful response");
		
		my $xs = XML::Simple->new();
		my $ref = $xs->XMLin($r_content, KeyAttr => { 'config-file' => 'id' }, ForceArray => [ 'config-file' ]);

		foreach my $config_id (keys %{$ref->{'config-file'}}) {

			my $dev_id	= $ref->{'config-file'}->{$config_id}->{'deviceId'};
			my $dev_uri	= $ref->{'config-file'}->{$config_id}->{'uri'};
			my $dev_name	= $ref->{'config-file'}->{$config_id}->{'deviceName'};
			my $dev_family	= $ref->{'config-file'}->{$config_id}->{'deviceFamily'};
			my $config_name	= $ref->{'config-file'}->{$config_id}->{'configFileName'};
			my $config_uri	= $ref->{'config-file'}->{$config_id}->{'latest-version'}->{'href'};
			my $config_ver	= $ref->{'config-file'}->{$config_id}->{'latestVersion'};
			
			show ("Storing config attibutes: [id $config_id] [$config_name] [v $config_ver] device: [id $dev_id] [$dev_name] [$dev_family]");
			show ("Storing config uri: [$config_id] [$config_uri]",DEBUG);

			$configs{$config_id}{'dev_id'}		= $dev_id;
			$configs{$config_id}{'dev_name'}	= $dev_name;
			$configs{$config_id}{'dev_uri'}		= $dev_uri;
			$configs{$config_id}{'dev_family'}	= $dev_family;
			$configs{$config_id}{'config_name'}	= $config_name;
			$configs{$config_id}{'config_uri'}	= $config_uri;
			$configs{$config_id}{'config_ver'}	= $config_ver;

			$cnt_configs++;

		}

	} elsif ($r_code == 204) {

		# handler for code 204 - added 07/06/2015 - SVB
		# no content - returned by space when no config files yet stored
		# need to go to "configuration management -> configuration file management -> backup configuration files (button at top)"
		
		show ("Response code indicates that device configurations have not been backed-up to space for this domain",CRITICAL);
		$cnt_error++;
		$RET = 1;

	} else {

		show ("Problem enumerating configurations - http response code: [$r_code: $r_content]",ERROR);
		$cnt_error++;
		$RET = 1;

	}

	return $RET;

}

################################
#
#       function:       download_configs
#
#       Purpose:        download enumerated configs
#
#	Parameters:     none
#
#
sub download_configs {

	show ("Downloading enumerated configurations from space server: [$space_server] [$space_user]");
	
	my $RET 		= 0;

	# needed to avoid server cert issues
	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}=0;


	my $space_client 	= REST::Client->new({ host => "$space_server" });
	my $h 			= { Authorization => 'Basic '.encode_base64("$space_user:$space_pass")};

	foreach my $config_id (keys %configs) {

		my $dev_id	= $configs{$config_id}{'dev_id'};
		my $dev_name	= $configs{$config_id}{'dev_name'};
		my $dev_family	= $configs{$config_id}{'dev_family'};
		my $config_uri	= $configs{$config_id}{'config_uri'};
		my $config_name	= $configs{$config_id}{'config_name'};
		my $config_ver	= $configs{$config_id}{'config_ver'};
		
		show ("Retrieving config id: [$config_id] [$config_name] device: [$dev_id] [$dev_name]");

		my $r 			= $space_client->GET($config_uri,$h);
		my $r_code		= $space_client->responseCode();
		my $r_content		= $space_client->responseContent();

		if ($r_code == 200) {

			my $xs 	= XML::Simple->new();
			my $ref = $xs->XMLin($r_content, KeyAttr => { 'config-file-version' => 'id' }, ForceArray => [ 'config-file-version' ]);

			if (keys %{$ref}) {

				my $rc_filename		= $ref->{'fileName'};
				my $rc_ts		= $ref->{'creationTime'};
				my $rc_ver_id		= $ref->{'versionId'};
				my $rc_content		= $ref->{'content'};
				my $rc_size		= $ref->{'configFileSize'};
				my $rc_uri		= $ref->{'uri'};
				my $rc_comment		= $ref->{'comment'};
				my $rc_md5		= $ref->{'latestMD5'};
				my $rc_id		= $ref->{'id'};

				#
				# derive filename to be written to output directory
				# use device id _ hostname _ configname (from space - ends in .conf)
				#
				my $local_file_name	= "$dev_id"."_"."$dev_name"."_"."$config_name";

				#
				# set path based - add device family if optioned
				#
				my $full_path		= $output_dir;
				$full_path 		.= "/".$dev_family	if ($use_dev_type);

				#
				# check date of config
				#
				if (check_config_time($rc_ts)) {

					#
					# write config - 0 on success
					#
					$rc_content		= hostname_fix($rc_content,$dev_name);
					my $w_ret		= write_config($full_path,$local_file_name,$rc_content);

				} else {

					show ("Configuration is older than user defined cuttoff: [$dev_name] [$rc_ts]");
					$cnt_old++;

				}

			} else {
				
				show ("Retrieved config is in improper format: [$dev_name] [$config_uri]",ERROR);
				$cnt_retrieve_error++;

			}

		} else {
	
			show ("Problem downloading configuration - http error code: [$r_code] : [$dev_name] [$config_uri]",ERROR);
			$cnt_retrieve_error++;
			$RET = 1;

		}

	}

	return $RET;

}

################################
#
#       function:       hostname_fix
#
#       Purpose:        replace hostname in config with one derived from space
#
#	Parameters:     config		- string; full configuration 
#
#	return:		modified config	- string
#
sub hostname_fix {

	my $config 	= shift;
	my $dev_name	= shift;

	#
	#	check for hostname fix user option
	#
	if ($hostname_fix) {
		
		show ("Replacing hostname in config with space devname: [$dev_name]");

		$config =~ s/host-name \S+;/host-name $dev_name;/g;

	}


	return $config;

}

################################
#
#       function:       write_config
#
#       Purpose:        download enumerated configs
#
#	Parameters:     config		- string; containing content to be written
#			filename	- string; full path of where to write 
#
#	return:		0 on success; 1 on failure
#
sub write_config {

	my $path	= shift;
	my $filename	= shift;
	my $config	= shift;

	#
	# make directory if it does not exist
	#
	unless ( -r $path ) {
		mkdir $path;
	}

	unless (open(FH,">",$path."/".$filename)) {

		show ("Problem writing config to path: [$path]",ERROR);
		$cnt_write_error++;
		return 1;

	}

	show ("Writing config: [$filename] to directory: [$path]");

	print FH $config;
	close FH;

	$cnt_downloaded++;

	return 0;

}
################################
#
#       function:       check_age
#
#       Purpose:        compare config time with user defined filter
#
#	Parameters:     config time stamp
#
#	return:		0 if old | 1 to download
#
sub check_config_time {

	my $config_ts		= shift;
	my $RET			= 0;

	my $cutoff		= $config_age;
	my $config_epoch	= get_epoch_from_date($config_ts);

	if ($config_epoch >= $cutoff) {
		$RET = 1;
	} 

	return $RET;

}

sub get_epoch_from_date {
	#########################################
	#
	# function		: _get_epoch_from_date
	#
	# purpose		: accept a date string and return unix epoch
	#
	# parameters		: date string
	#
	# return		: unix epoch
	#
	#########################################

	my $date_str	= shift;
	my $epoch	= 0;

	$epoch	= parsedate($date_str);

	return $epoch;

}

################################
#
#	USAGE
#
sub usage {

	my $app = basename $0;

	print <<EOF;

	Skybox to Junos Space Integration
	Pull Device Configurations from Junos Space

	USAGE: 	$app -s <space server> -u <username> -p <password> -o <output directory> [-t] [-v] [-h]
		
		Required: 
		-s | --space-server		space server to connect to (in the form of http(s)://server:port)
		-u | --space-user		space username 
		-p | --space-pass		password for authenticating the username
		-o | --output-directory		configuration download directory

		Optional:
		-d | --device-api		pull configs using the device api rather than using stored configs 
						(gets live configs with "show inheritance" directive - XML format)
		
		-t | --device-type-subdir	create subdirectories under download directory based on device type
		-a | --age			age in days for config download filter (this many days or newer; default (all))
						(invalid when using -d above)

		-r | --replace-hostname		replace config hostname with one derived from space
						(invalid when using -d above)
		
		-v | --verbose			debug (verbose) output
		-h | --help			this help

EOF
	exit 1;

}


