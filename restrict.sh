#!/bin/bash
## 
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
## 
## version 1.12 // th(at)bogus.net
##
## Copyright 2022 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## prepend the following in Marty McSandfly's .ssh/authorized_keys public key: 
## command="/usr/local/bin/restrict.sh",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding 
##
## copy this script to /usr/local/bin/restrict.sh with the correct umask (e.g. chmod 755)
##
## NOTE - recent releases of Sandfly let administrators rename the binary that is copied to the endpoint
## NOTE - if this is done, the regex patterns within this script MUST MATCH your admin's choice(s)!
## NOTE - see examples within the script below (^#:) and make the necessary changes
## 
## @sandflysecurity: would be awesome if you posted the sha256sums of your binaries somewhere!
##


# list of valid hashes (might need expanding depending on your install)
vhashes=$(cat <<EOF
e53f43e2bfc701f631e29db8c940e2bf725fe0639a48c1b01b87df843c4d2c2e
5c2d3e8f8e5ce35162499550c94a7f08301dafd2a16acf51178f38e10d5ab1b2
4ddcd0c5ce35fd87696265f45128398a7bea0c49245b3b4c1597887eba18942d
EOF
)

cmd="$SSH_ORIGINAL_COMMAND"

if [[ $cmd =~ ^.*($HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}).*$ ]]
then
	dir=${BASH_REMATCH[1]}
else
#:	if [[ $cmd =~ ^sudo.*(sandfly|botfly).*$ ]]
	if [[ $cmd =~ ^sudo.*sandfly.*$ ]]
	then
		logger "$(basename $0) fail: can't determine directory"
# debug		logger "$(basename $0) fail: can't determine dir: $cmd"		
		exit 1
	fi
fi

#: run through whitelist check of commands (default binary name + "botfly"; match your setup!)
#if [[ $cmd =~ ^/usr/lib/openssh/sftp-server$ || \
#	$cmd =~ ^pwd$ || \
#	$cmd =~ ^(sudo\ )/bin/sh\ -c\ \"(/bin|/usr/bin)/whoami\"$ || \
#	$cmd =~ ^/(bin|usr/bin)/id$ || \
#	$cmd =~ ^/(bin|usr/bin)/id\ -u$ || \
#	$cmd =~ ^/(bin|usr/bin)/uname\ -m$ || \
#	$cmd =~ ^/(bin|usr/bin)/uname$ || \
#	$cmd =~ ^/(bin|usr/bin)/touch\ [\'\"][a-f0-9]{10}[\'\"]$ || \
#	$cmd =~ ^/(bin|usr/bin)/rm\ [\'\"][a-f0-9]{10}[\'\"]$ || \
#	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]/(bin|usr/bin)/touch\ [a-f0-9]{10}[\'\"]$ || \
#	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]/(bin|usr/bin)/rm\ [a-f0-9]{10}[\'\"]$ || \
#	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+cd\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;[\ ]*$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/(sandfly|botfly)[\-\ a-z0-9]+[\'\"]$ || \
#	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/(sandfly|botfly)\ -x\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\'\"]$ || \
#	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/(sandfly|botfly)\ -k\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\.pid[\'\"]$ ]]

if [[ $cmd =~ ^/usr/lib/openssh/sftp-server$ || \
	$cmd =~ ^pwd$ || \
	$cmd =~ ^(sudo\ )/bin/sh\ -c\ \"(/bin|/usr/bin)/whoami\"$ || \
	$cmd =~ ^/(bin|usr/bin)/id$ || \
	$cmd =~ ^/(bin|usr/bin)/id\ -u$ || \
	$cmd =~ ^/(bin|usr/bin)/uname\ -m$ || \
	$cmd =~ ^/(bin|usr/bin)/uname$ || \
	$cmd =~ ^/(bin|usr/bin)/touch\ [\'\"][a-f0-9]{10}[\'\"]$ || \
	$cmd =~ ^/(bin|usr/bin)/rm\ [\'\"][a-f0-9]{10}[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]/(bin|usr/bin)/touch\ [a-f0-9]{10}[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]/(bin|usr/bin)/rm\ [a-f0-9]{10}[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+cd\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;[\ ]*$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly[\-\ a-z0-9]+[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\ -x\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\ -k\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\.pid[\'\"]$ ]]
then

#:	if [[ $cmd =~ ^sudo.*(sandfly|botfly).*$ ]]
	if [[ $cmd =~ ^sudo.*(sandfly).*$ ]]
	then
		sfbinaryname=${BASH_REMATCH[1]}
		if [[ `/usr/bin/sha256sum $dir/$sfbinaryname` =~ ^([0-9a-f]{64}).*$ ]]
		then
			sfhash=${BASH_REMATCH[1]}
			for hash in $vhashes
			do
				if [[ $hash == $sfhash ]]
				then
					eval $cmd
					exit 0
				fi
			done
		fi
	else
		eval $cmd
		exit
	fi
else
	logger "$(basename $0) didn't pass command whitelist or hash check"
# debug	logger "$(basename $0) didn't pass whitelist: $cmd"
	exit 1
fi
