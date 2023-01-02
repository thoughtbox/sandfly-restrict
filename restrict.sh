#!/usr/bin/env bash
## 
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
## 
## version 1.15 // th(at)bogus.net
##
## Copyright 2022 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## prepend the following in Marty McSandfly's .ssh/authorized_keys public key: 
## command="/usr/local/bin/restrict.sh",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding 
##
## copy this script to /usr/local/bin/restrict.sh with the correct umask (e.g. chmod 755)
##
## NOTE - recent releases of Sandfly let administrators rename the binary that is copied to 
## NOTE - the endpoint. in this case, the regex pattern below MUST MATCH your admin's choice(s)!
##
sfbinnames="sandfly|botfly"

## the external commands cat, basename, logger and sha512sum should be found here
##
PATH="/usr/bin:/bin"

## list of valid hashes (might need expanding depending on your cpu architectures); these are aarch64 and amd64 for v4.3.2
##
vhashes=$(cat <<EOF
2143104a62ac1b75ae5f7f2632f3809636cef6e4e09f3d879db53194662ec62c638f4046b68bdc8c32a7a2095a5ae099b4d0d9578322af9950714d0e55970cab
2618fc110b297c152ac12bc8fe678380fffad68e7ad2e9286657cff9618dd6be21ed7f93abb6c0fa03c7fb0a27349e15d07779fad8594a1a1dc721dba6d17622
EOF
)

cmd="$SSH_ORIGINAL_COMMAND"

if [[ $cmd =~ ^.*($HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}).*$ ]]
then
	dir=${BASH_REMATCH[1]}
else
	if [[ $cmd =~ ^sudo.*($sfbinnames).*$ ]]
	then
		logger "$(basename $0) fail: can't determine directory"
		exit 1
	fi
fi

## run through whitelist check of commands 
if [[ $cmd =~ ^/usr/(lib|libexec)/openssh/sftp-server$ || \
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
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+cd\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;[\ ]*$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($sfbinnames)[\-\ a-z0-9]+[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($sfbinnames)\ -x\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\'\"]$ || \
	$cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($sfbinnames)\ -k\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\.pid[\'\"]$ ]]
then
	if [[ $cmd =~ ^sudo.*($sfbinnames).*$ ]]
	then
		sfbinaryname=${BASH_REMATCH[1]}
		if [[ $(sha512sum $dir/$sfbinaryname) =~ ^([0-9a-f]{128}).*$ ]]
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
			logger "$(basename $0) $sfbinaryname didn't pass hash check"
			exit 1
		fi
	else
		eval $cmd
		exit 0
	fi
else
	logger "$(basename $0) input didn't pass command whitelist"
	exit 1
fi
