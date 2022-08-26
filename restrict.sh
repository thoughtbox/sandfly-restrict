#!/bin/bash
## 
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
## 
## version 1.05 // th(at)bogus.net 
##
## Copyright 2022 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## prepend the following in Marty McSandfly's .ssh/authorized_keys public key 
## command="/usr/local/bin/restrict.sh",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding 
##
## note: 'no-pty' cannot be used in the above line
##

# list of valid hashes (first is a test hash -- of /usr/bin/sleep; you should delete this)
vhashes="3e27ced4ece1aab2cf2af72ad66587cfeb3f9ea70dd07472714ffb805a0009f4 e53f43e2bfc701f631e29db8c940e2bf725fe0639a48c1b01b87df843c4d2c2e"

cmd="$SSH_ORIGINAL_COMMAND"

# get temporary directory if the command contains 'sandfly'
if [[ $cmd =~ ^.*($HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}).*$ ]]
then
	dir=${BASH_REMATCH[1]}
else
	if [[ $cmd =~ ^sudo.*sandfly.*$ ]]
	then
		logger "$(basename $0) fail: can't determine dir: $cmd"
		exit 1
	fi
fi

# run through whitelist check
if [[ $cmd =~ ^/usr/lib/openssh/sftp-server$ || \
	$cmd =~ ^pwd$ || $cmd =~ ^(sudo\ )/bin/sh\ -c\ \"whoami\"$ || \
	$cmd =~ ^(/bin|/usr/bin)/id$ || \
	$cmd =~ ^(/bin|/usr/bin)/id\ -u$ || \
	$cmd =~ ^(/bin|/usr/bin)/uname\ -m$ || \
	$cmd =~ ^(/bin|/usr/bin)/uname$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+cd\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;[\ ]*$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly[\-\ a-z0-9]+[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\ -x\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\ -k\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\.pid[\'\"]$ ]]
then

    # perform a hash comparison
	if [[ $cmd =~ ^sudo.*sandfly.*$ ]]
	then
		if [[ `/usr/bin/sha256sum $dir/sandfly` =~ ^([0-9a-f]{64}).*$ ]]
		then
			sfhash=${BASH_REMATCH[1]}
			for hash in $vhashes
			do
				if [[ $hash == $sfhash ]]
				then
					eval $cmd
					exit
				fi
			done
		fi
	else
		eval $cmd
		exit
	fi
else
	logger "$(basename $0) didn't pass whitelist: $cmd"
	exit 1
fi
