#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.20 // th(at)bogus.net
##
## Copyright 2023 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##

## Update this variable if your Agent Binary Names setting in the
## Server Configuration is not using the default 'sandfly' value.
## For multiple names this value must be in this format: NAME1|NAME2|NAME3
agentbinarynames="botfly|sandfly"

## Update this variable if the sftp-server location is different.
sftpserverpath="/usr/(lib|libexec)/openssh/sftp-server"

## Update this variable to reflect the paths to these external commands:
##   cat, basename, logger, sha512sum, awk
PATH="/usr/bin:/bin"

cmd="$SSH_ORIGINAL_COMMAND"

## list of valid hashes (ref. https://github.com/sandflysecurity/sandfly-setup/blob/master/sandfly.agent.sha512.txt);
vhashes512=$(awk '{print $1}' <<EOF
2e5bd264015ef81705ded366cd803a29a07fb49a04abb38c6ca16f9af9155b1bfdd04066e8cf9945a091ed558818514ef00866f2086fe5b7de73733266b05023 *sandfly.386
b82d50ec96bc631098dbfc5026400acea74439a6940ea4ec38a8446716547c5d32366cb47ff05ae1ecc28df85fb0d557891426253dd5a3feecbf2909433b00e1 *sandfly.amd64
5553e6e2e207c586a4d059a5200f8ec39df68eabf0f02596be0c99953692e02650d9bce3eb7d43cc798a65dfccc7b8f7799dfba6e238bffadbc47553a2edece1 *sandfly.arm
5553e6e2e207c586a4d059a5200f8ec39df68eabf0f02596be0c99953692e02650d9bce3eb7d43cc798a65dfccc7b8f7799dfba6e238bffadbc47553a2edece1 *sandfly.arm5
dd9f5abcb643c5e241f92c96be1c5defd085bcdc1caf4e2574dd1d34918af8ff2dab9287e2928b11d67dcf14b7e3f00a030c7d57f1320e4184e4b99ecf007cc0 *sandfly.arm6
99ae43c94190969b477fe3608386e8bed3786ea4863aea733062b83e368232bc6d1abac4fc523aa06cea64a2ba92da1e3b85c111fd0032d13e94731098602883 *sandfly.arm64
f4a663e2de1dede843b7be54e19028df73ed84d901a587c325c845f9d5304333d95d43543ed1eb4dbe7ea85634cd2e8fdce87f4e88f02564eaa88c6ffabd5371 *sandfly.arm7
0f1a8cc6ed12169721b4a642a676c4ce08cb78058968fbe1850d9b13762cd400d6688ac338da73effb8ffeb53bbdea296fcd0acc788e110e1c513b543b36d5f6 *sandfly.mips
c34d5bc012d1d6650ef9b1e12163929fbb4958e5f5d996e255c5c041076992bf96cc507f36daf9e74ecd32dfd1ff2f16b700d52b71c8022963afdd1a17629f44 *sandfly.mips64
EOF
)

# get temporary directory if the command contains the agentbinaryname
if [[ $cmd =~ ^.+?($HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}).+$ ]]
then
    dir=${BASH_REMATCH[1]}
else
    if [[ $cmd =~ ^(.+)??sudo\ (-S\ )??\/bin\/sh\ -c\ [\'\"].+\/${agentbinarynames}\ .+[\'\"]$ ]]
    then
        logger "$(basename $0) fail: can not determine directory"
        exit 1
    fi
fi

# perform command whitelist check
if [[ $cmd =~ ^pwd$ || \
    $cmd =~ ^echo\ \"DATA_START\ [a-f0-9]{32}\"\ &&\ echo\ \"\w+=\`\/usr\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/usr\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`uname\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/usr\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/usr\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"\w+=\`pwd\ 2\>\/dev\/null\`\"\ &&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^(sudo\ )?/bin/sh\ -c\ [\'\"](/bin/|/usr/bin/)?whoami[\'\"]$ || \
    $cmd =~ ^(/bin/|/usr/bin/)?id( -u)?$ || \
    $cmd =~ ^(/bin/|/usr/bin/)?uname( -m)?$ || \
    $cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"](/bin/|/usr/bin/)?touch\ [0-9a-fA-F]{10}[\'\"]$ || \
    $cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"](/bin/|/usr/bin/)?rm\ [0-9a-fA-F]{10}[\'\"]$ || \
    $cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]cd\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;[\ ]*$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/${agentbinarynames}\ (\-l\ )?\-\z\ [0-9]\ \-t\ [0-9]\ \-n\ (\-)?[0-9]{1,2}\ \-i(\ )?[\'\"]$ || \
    $cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/${agentbinarynames}\ \-x\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\'\"]$ || \
    $cmd =~ ^sudo\ /bin/sh\ -c\ [\'\"]$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/${agentbinarynames}\ \-k\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\.pid[\'\"]$ || \
    $cmd =~ ^echo\ [\'\"]DATA_START\ [a-f0-9]{32}[\'\"]\ \&\&\ sudo\ -S\ /bin/sh\ -c\ [\'\"](/bin/|/usr/bin/)?id[\'\"]\ \&\&\ echo\ [\'\"]DATA_END\ [a-f0-9]{32}[\'\"]$ || \
    $cmd =~ ^echo\ [\'\"]DATA_START\ [a-f0-9]{32}[\'\"]\ \&\&\ sudo\ -S\ /bin/sh\ -c\ [\'\"]cd\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;[\ ]*$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/${agentbinarynames}\ (\-l\ )?\-\z\ [0-9]\ \-t\ [0-9]\ \-n\ (\-)?[0-9]{1,2}\ \-i(\ )?[\'\"]\ \&\&\ echo\ [\'\"]DATA_END\ [a-f0-9]{32}[\'\"]$ || \
    $cmd =~ ^echo\ [\'\"]DATA_START\ [a-f0-9]{32}[\'\"]\ \&\&\ sudo\ -S\ /bin/sh\ -c\ [\'\"]$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/${agentbinarynames}\ \-x\ $HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\'\"]\ \&\&\ echo\ [\'\"]DATA_END\ [a-f0-9]{32}[\'\"]$ || \
    $cmd =~ ^$sftpserverpath$ ]]
then
    # perform a hash comparison when using sudo along with a valid agent
    if [[ $cmd =~ ^(echo\ .+\ )??sudo\ .+\/(${agentbinarynames})\ .+?$ ]]
    then
        agentbinaryname=${BASH_REMATCH[2]}
        if [[ $(sha512sum $dir/$agentbinaryname) =~ ^([0-9a-f]{128}).*$ ]]
        then
            checksumhash=${BASH_REMATCH[1]}
            for hash in $vhashes512
            do
                if [[ $hash == $checksumhash ]]
                then
                    eval $cmd
                    exit 0
                fi
            done
            # Log event and exit if no valid hashes were matched
            logger "$(basename $0) fail: $agentbinaryname agent did not pass hash check"
            exit 1
        fi
    else
        eval $cmd
        exit 0
    fi
else
    # Log event and exit if no valid commands were matched
    logger "$(basename $0) fail: input did not pass command whitelist"
    exit 1
fi
