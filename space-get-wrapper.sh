#!/bin/sh

function usage {
	echo
	echo "	USAGE: $0 <space server> <space_user> <space_pass> <output_directory> <optional: -t -v -h>"
	echo
	exit 1
}

space_server=$1
space_user=$2
space_pass=$3
output_dir=$4
options=$5
thisdir=$(dirname $0)
perl=$thisdir/space-get.pl

space_server="https://192.168.1.10"
#space_user=super
#space_pass="q1w2e3R$"
space_user=skybox
space_pass="q1w2e3R$"
output_dir=/opt/FRB/space/configs
options="-v -t -r"

if [ ! $space_server ]||[ ! $space_user ]||[ ! $space_pass ]||[ ! $output_dir ] 
then
	usage;
fi
if [ ! -w $output_dir ]
then
	echo
	echo "	Download directory either does not exist or is not writable !!!"
	usage;
fi

echo "Running junos space downloader ..."
perl $perl -s $space_server -u $space_user -p $space_pass -o $output_dir $options

if [ $? -eq 0 ]
then
	echo "Wrapper completed successfully"
	RET=0
else
	echo "Problems running space downloader"
	RET=1
fi

exit $RET
