#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.23 // th(at)bogus.net
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
##   cat, basename, logger, sha512sum, awk, ls, tr, pwd, head, tail
PATH="/usr/bin:/bin"

cmd="$SSH_ORIGINAL_COMMAND"

## list of valid hashes (ref. https://github.com/sandflysecurity/sandfly-setup/blob/master/sandfly.agent.sha512.txt);
vhashes512=$(awk '{print $1}' <<EOF
f7cf63e94843ff00c74e5b9afc034b6d51985c0056e6a314dcbfdeffc8403f80b331fa383238fe6b2ace586f53f24397d576d5e346d4068cebcce37bae816e07 *sandfly.386
166e1e391de7405dac70c8cef5108b8d732ca5bc36958e449889def99dccbb09fff495d245a57460e816331356581e58ea94878ae486236ba0067a3ae1ec5274 *sandfly.amd64
4a597ca55ea926b1b46a31de27a1a1e7cd7d65c86bc2e62eed3835b8beaefacfdf8194941a75fc54bd153b91f2a4a7315448d0f2e4f067e8a04492a2cab669e8 *sandfly.arm
e40b814fac192f76a9ae3a02693c4b11c7fc32d4d9ab55e6fde755580f1b1862b3c32120652a8380d320e28f9fe934149251aa736d7d569ac428d23b5e7f09ce *sandfly.arm6
c630d3d7a9f2c9bebd0c6b3ed30f63efa27fa82783207ff6d6e2ea19d7acdd3c84e48b2da4aee35c002d88ee12be130efd3ca3ee56a71cee58e375853ef2494f *sandfly.arm64
2588db8f37f51df2c8daa4eb9df148ece8f03b405a41deb5cbe50253b3c7137e868089e3747b55b3b44c73a30d4134809e1133009d4fd149a84991068618f801 *sandfly.arm7
bd0c949eb032020f445038d831659843b2aca5eb71887d510a15e3c22886b30806f0edb307c5dbc764d2bf92b608611e0e9438d230a179bd663971ec714eed33 *sandfly.mips
1a09776dc5f835d277e6a1fba3f00a7dc663ed2c4f2d620deac1e239e15c93869483bd4fe7ae4a28da9c64c3854fc84b532681bd5529dd197d06046d08ba1587 *sandfly.mips64
cf1f9e23a94053e3c693ed267e76103bfb93d048a62a7db19793bfb609d2e26bf9003f8342a74f6522c37ca631bd06e2d89a32f16b2c0a093d2feaeac25124e5 *sandfly.mips64le
0077bfac4a1d3593d4667ce2e628b276c74acd69179cc448adeb8460ed4294f79bfb6f83c7734210493e83e00b41e8351c75ae133a12b7e12305a6433b09efd7 *sandfly.mipsle
EOF
)

# get temporary directory if the command contains the agentbinaryname
if [[ $cmd =~ ^.+?($HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}).+$ ]]
then
    dir=${BASH_REMATCH[1]}
else
    if [[ $cmd =~ ^(.+)??sudo\ (-S\ )??\/bin\/sh\ -c\ [\'\"].+\/${agentbinarynames}\ .+[\'\"]$ ]]
    then
        logger "$(basename $0) fail: cannot determine directory"
        exit 1
    fi
fi

if [[ $cmd =~ ^pwd$ || \
    $cmd =~ ^echo\ \"DATA_START\ [0-9a-f]{32}\"\ \&\&\ echo\ \"[A-Z_]+=\`\/usr\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/head\ -c\ 6\ \/bin\/ls\|\ \/bin\/tail\ -c\ 1\ \|\ \/bin\/tr\ \"$'\001\002'\"\ \"LB\"\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/head\ -c\ 6\ \/usr\/bin\/ls\|\ \/usr\/bin\/tail\ -c\ 1\ \|\ \/usr\/bin\/tr\ \"$'\001\002'\"\ \"LB\"\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`head\ -c\ 6\ \/bin\/ls\|\ tail\ -c\ 1\ \|\ tr\ \"$'\001\002'\"\ \"LB\"\ 2\>\/dev\/null\`\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ sudo\ -S\ \/bin\/sh\ -c\ \"(|\/usr\/bin\/|\/bin\/)id\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ sudo\ -S\ \/bin\/sh\ -c\ \"cd\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/(${agentbinarynames})\ [-\ a-z0-9]+\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ sudo\ -S\ \/bin\/sh\ -c\ \"$HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/(${agentbinarynames})\ -k\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/sandfly.pid\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ sudo\ -S\ \/bin\/sh\ -c\ \"$HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/(${agentbinarynames})\ -x\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^$sftpserverpath$ ]]
then
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
            logger "$(basename $0) fail: $agentbinaryname agent did not pass hash check"
            exit 1
        fi
    else
        eval $cmd
        exit 0
    fi
else
    logger "$(basename $0) fail: input did not pass command whitelist"
    exit 1
fi
