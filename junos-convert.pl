#!/usr/bin/perl
#
#
# (c) SkyboxSecurity 2015
#
# Name		: space-get.pl
# Date		: June 24, 2015
# Version	: V20150706_00001
# Author	: Scott Bianco
#
# Version 2	: 07/06/2015	SVB
# 		  Added handling of http response code 204: no content
# 		  this code is returned by space when no config files have been stored in the associated domain
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

#use lib "/opt/LIBS";
use functions;

#####
# libraries for RESTFul APIs
use MIME::Base64;
#use XML::Simple qw(:strict);
use XML::Simple;

#####
# standard libraries needed
use Getopt::Long qw(:config bundling_override passthrough);
use File::Basename;
use Time::ParseDate;
use Data::Dumper;

#####

#####
# script variables
my $VERSION	= "Junos Space Integration - Version: V20150706_00001";
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
my $cnt_downloaded	= 0;
my $cnt_retrieve_error	= 0;
my $cnt_write_error	= 0;
my $cnt_error		= 0;
my $cnt_old		= 0;

#####
# parameters
my $input_file		= "";
my $output_dir		= "";
my $xml			= 0;

#####
# parse parameters
$RET_opt	= GetOptions	
			(	"v|verbose"		=>	\$DEBUG,
				"h|help"		=>	\$get_help,
				"i|input-file=s"	=>	\$input_file,
				"o|output-directory=s"	=>	\$output_dir,
				"x|xml"			=>	\$xml,
			);

#####
# error check input
unless (($input_file)&&($output_dir))	{ &usage; }
if ($get_help)		{ &usage; }

unless (-e $output_dir) {
	show ("Problem accessing output directory: [$output_dir]",CRITICAL,1);
}

#####
# main

#
#	Set script wide parameters
#
&_set_debug_flag($DEBUG);

my $RET = 0;
my @out = ();
if ($xml) {
	&read_xml;
	print @out;
} else {
	@out	= &read_file;
	$RET 	= &write_out;
}

exit $RET;

##################################################################################################

################################
################################

#
#	FUNCTIONS
#

sub read_xml {

	my $xs = XML::Simple->new();
	#my $ref = $xs->XMLin($input_file,ForceArray => 1);
	my $ref = $xs->XMLin($input_file);

	#
	# force order for known stanzas
	#
	#blastit($ref,"version");
	#blastit($ref,"system");
	#blastit($ref,"snmp");
	blastit($ref,"security");

	#print keys $ref;

}

sub blastit {

	my $stanza 	= shift;
	my $top_key	= shift;
	my $m	   	= shift || 0;
	my $b_noprint	= shift || 0;
	my $prefix	= shift || "";

	# set indent for each subsequent stanza
	my $sp  = "";
	$sp	= "  "x$m if ($m);
	
	#
	# recursive hash assignment
	#
	my $sub_stanza = $stanza->{$top_key};

	#print Dumper $sub_stanza;

	if (ref($sub_stanza) eq "HASH") {

		$m++;	# increment spacing

		#
		# special treatment for combined lines
		#
		if ($top_key =~ /(^pool$|^user$)/) {
			#push (@out,"$sp"."$top_key ");
			$prefix = "$top_key ";
		} else {
			push (@out,"$sp"."$prefix"."$top_key {\n")	unless ($b_noprint);
			$prefix = "";
		}
		
		foreach my $key (keys %{$sub_stanza}) {
	
			#next if ($key =~ /name/);

			if (((ref($sub_stanza->{$key}) eq "HASH"))&&(keys %{$sub_stanza->{$key}})) {
				
				#
				# handle special cases
				#
				if ($sub_stanza->{$key}->{'prefer'}) {
					
					push (@out,"$sp  "."$key prefer;\n");

				#
				# if name is the subkey - add to previous line
				#
				} elsif (($sub_stanza->{$key}->{'name'})) {

					my $name = $sub_stanza->{$key}->{'name'};
					
					#
					# special case to force next heiarichal level
					#
					if ($key =~ /^address\-book$/) {
						print "address-book\n";
						blastit($sub_stanza,$key,$m);
					} else {
						blastit($sub_stanza,$key,$m,1);
						push (@out,"$sp"."$key $name;\n");
					}

				#
				# if address-book is the key and  address is the subkey - add to previous line
				#
				} elsif (($key eq "address-book")&&($sub_stanza->{$key}->{'address'})) {

					my $name = $sub_stanza->{$key}->{'address'};
					
					push (@out,"$sp"."$key $name;\n");
					blastit($sub_stanza,$key,$m,1);
											

				#
				# default case
				#
				} else {
				
					blastit($sub_stanza,$key,$m,0,$prefix);

				}
	
			} else {
			
				my $val = "";
				
				#
				# only grab the value if not a subhash
				#
				$val = $sub_stanza->{$key} unless (ref($sub_stanza->{$key}) eq "HASH");
				
				#
				# special treatment for quoted strings
				#
				$val = "\"".$val."\""	if (($val)&&($key =~ /(^encrypted\-password$|^match$)/));
				
				#
				# add space between key and val if val is populated
				#
				$val = " ".$val if ($val);

				push (@out, "$sp  "."$key"."$val; [a]\n")	unless ($key eq "name");
	
			}

		}
				
		push (@out, "$sp"."}\n")	unless ($b_noprint);

	} else {
		push (@out, "$sp"."$top_key "."$sub_stanza;\n");
	}

	#
	# clear out this item from hash to avoid duplication
	#
	delete $stanza->{$top_key};

}

sub read_file {

	unless (open (FH,"<",$input_file)) {
		show ("Problem opening input file: [$input_file]",CRITICAL,1);
	}

	my @wholefile = <FH>;
	close FH;

	my $b_ob 	= 0;	# mark open bracket

	my $max = @wholefile;

	show ("Interating times: [$max]");

	for (my $i=0;$i<$max;$i++) {
		
		my $line 	= $wholefile[$i];
		my $nl 		= "";

		# special treatment for interface unit 
		if ($line =~ /\s{4}(\s*)<interface>/ ) {
			
			my $sp 	= $1;
			$i++;
			$line = $wholefile[$i];
			if ($line =~ /<name>(\S+)</) {
				$nl = "$sp"."$1 {\n";
			}

		# special treatment for interface unit 
		} elsif ($line =~ /\s{4}(\s*)<(unit)>/) {

			my $sp 	= $1;
			my $tag	= $2;
			print "found: [$tag]\n";
			$i++;
			$line = $wholefile[$i];
			if ($line =~ /<name>(\S+)</) {
				$nl = "$sp"."$tag $1 {\n";
			}
		
		# special treatment for interface family
		} elsif ($line =~ /\s{4}(\s*)<(family)>/) {

			my $sp 	= $1;
			my $tag	= $2;
			print "found: [$tag]\n";
			$i++;
			$line = $wholefile[$i];
			if ($line =~ /<(\S+)>/) {
				$nl = "$sp"."$tag $1 {\n";
			}
		
		# special treatment for interface address
		} elsif ($line =~ /\s{4}(\s*)<(address)>/) {

			my $sp 	= $1;
			my $tag	= $2;
			print "found: [$tag]\n";
			$i++;
			$line = $wholefile[$i];
			if ($line =~ /<name>(\S+)<\/name>/) {
				$nl = "$sp"."$tag $1;\n";
			}

		# disabled tag
		} elsif ($line =~ /\s{4}(\s*)<disable/) {

			$nl = $1."disable;\n";

		# close bracket
		} elsif ($line =~ /\s{4}(\s*)<\//) {
			$nl 	= "$1"."}\n";	
			#$b_ob	= 0;

		# name tag
		} elsif ($line =~ /\s{4}(\s*)<name>(\S+)<\/name>/) {
			$nl = $1.$2.";\n";

		# description tag (wrap in quotes)
		} elsif ($line =~ /^\s{4}(\s*)<(description)>(.+)<\/description>/) {
			$nl 	= "$1"."$2 \"$3\";\n";

		# open and close bracket on same line
		} elsif ($line =~ /^\s{4}(\s*)<([a-zA-Z0-9\-]+)>(\S+)<\//) {
			$nl 	= "$1"."$2 $3;\n";

		# open bracket
		} elsif ($line =~ /\s{4}(\s*)<([a-zA-Z0-9\-]+)>/) {
			$nl 	= $1.$2." {\n";
			$b_ob	= 1;
		
		}

		push (@out,$nl);

	}

	return @out;

}

sub write_out {

	my $file = basename($input_file);
	my $out_file = $output_dir."/".$file.".conf";

	show ("Writing config to output file: [$out_file]");

	unless (open (FH,">",$out_file)) {
		show ("Problem opening file for writing: [$out_file]",CRITICAL);
		return 1;
	}

	print FH @out;
	close FH;

	return 0;

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

	USAGE: 	$app -i <input file> -o <output directory> [-v] [-h]
		
		Required: 
		-i | --input-file		junos configuration in XML format
		-o | --output-directory		converted configuration output directory

		Optional:
		-x | --xml			use xml parsing (using XML::Simple) rather than textual parsing
		-v | --verbose			debug (verbose) output
		-h | --help			this help

EOF
	exit 1;

}


