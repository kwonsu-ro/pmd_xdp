#!/bin/sh

BASENAME=`basename $0`
LIST_NIC_1=$1
LIST_NIC_2=$2

function pmd_init_yara_rule( )
{
	echo "Start initialise Yara Rules"

	YR_DIR="../yara_rules"
	YR_FILE="compiled_rules.yarc"

	if [ ! -d $YR_DIR ];then
		echo "	Downloading downloading Yara Rule from https://github.com/Yara-Rules/rules"
		git clone https://github.com/Yara-Rules/rules $YR_DIR 1> /dev/null 2> /dev/null
	fi

	cd $YR_DIR

	echo "	Create Yara Rule File for Testing"
	cat << EOF > pmd_test.yar
rule SimpleMalwareTest {
    meta:
        description = "YARA 테스트 셈플"
        date = "2025-07-05"
    strings:
        \$malware = "malicious" nocase
    condition:
        \$malware
}
EOF
	echo "	    Yara Test Rule file : pmd_test.yar"

	echo "	Create Yara Compile Rules"
./index_gen.sh 1> /dev/null 2> /dev/null
yarac index.yar compiled_rules.yarc 1> /dev/null 2> /dev/null
cp -dpr $YR_FILE /etc/yara/rules/$YR_FILE 1> /dev/null 2> /dev/null
cd - 1> /dev/null 2> /dev/null

	echo "	    Yara Compile Rule path : /etc/yara/rules/$YR_FILE"
	echo "End initialise Yara Rules"
}

function pmd_init_nic( )
{
	echo "Start initialise NIC"

	if [ -z $LIST_NIC_1 ] || [ -z $LIST_NIC_2 ];then
		echo "	Usage: $BASENAME <NIC 1> <NIC 2>"
		exit 1;
	fi

	LIST_NIC="enp0s3 enp0s8"

	for sub in $LIST_NIC;do
		CHK=`ifconfig $sub 2> /dev/null`

		if [ -z "$CHK" ];then
			echo "	No such ethernet : $sub"
			exit 1;
		fi

		xdp-loader unload -a $sub 1> /dev/null 2> /dev/null

		ip link set $sub promisc on 1> /dev/null 2> /dev/null

		ethtool -K $sub tso off gso off gro off lro off rxvlan off 1> /dev/null 2> /dev/null

		echo "	Initialise ethernet : $sub"
	done

	echo "End initialise NIC";echo ""
}

pmd_init_nic
pmd_init_yara_rule
