#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.40 // th(at)bogus.net
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
8ffb03315e8090591b36607c36f06510e1ceb3833b90478b744254450f4045b55bef917700a60f532ea5938cf844d6f21f5dc647d38f0cdf9a14905ca4b1ee95 *sandfly.386
ba64bb1fdd32c24e945a204f29b61c6c2e779856036ac963e68dce21f2a812b68e6a18f0874b227e39f084805522d3ad87163bd580d5bd36ca0b65794f2c2f1a *sandfly.amd64
d4497c0bfb8b6c23dc7ef5de59f974c3a0992b8f1278d04c95ecc5f4f58e69738df1716293dba2869dec215b203c4095c0dbfc18114407230f78e2d86e99e7b6 *sandfly.arm
d4497c0bfb8b6c23dc7ef5de59f974c3a0992b8f1278d04c95ecc5f4f58e69738df1716293dba2869dec215b203c4095c0dbfc18114407230f78e2d86e99e7b6 *sandfly.arm5
c87ef043e55226207cc989f08175b54df4596808603734de9924524648ca7eca6c0d303ba65cbdb40c63c0bd2c9fba2863ab72fe7e9f346ed8036e5c1eed88f1 *sandfly.arm6
a2816ba2adc480ae9040f37ee79c73432ab5bc76d10dad059eb073f0346e0e9c21291a2197a5ae25aafac35d079e87255601a08f188bf9ede6163fa96ecc161c *sandfly.arm64
027f0b9a5b0f5aa55a8f4701425e0d96f8a682d0ab0a098f3d1931133da4075c536484e2ea08fa2065ea8d633a823bda9160c579a7467e1c2d56e6b83406f824 *sandfly.arm7
60f4ab41c630ffe0976ad70442a7a627457881766b353b30dd305bf87d54d80216c568d1aa10e53cdac805163a28bcbed6d881378401a0f82a7b18bb06f70629 *sandfly.mips
e8bb8a3791a88dee4783bf97cddcca40d38441f5f97ababb54ec9b29fbabfb31a3a453e1b74383cd6edb2435653e3fcef49964ee849c89f16df893119623400f *sandfly.mips64
bc80f12b3095ad83b5b8c21aab31189dc78ab77e57273291eb70044f7b78525af0c40f6aae7c1cdbe0f35a21f25ee396ae00e68922babf1372d548233d01f138 *sandfly.mips64le
771c0d39bd612f7400de27c701a8f85e92bfc4a5c433836b5161c10e6be82bf046fbc9fed69ba656e7364beefba557b2f1e13638a39b90a0ec07cc455fe7cfcb *sandfly.mipsle
51be588fbcbf06bc663b6af7af0f2ae3b32601cf743c6318463e64771a4463f8b94f89c33e8ed862cb685ea4a42c63a224aae3b42bacad05e2bf3dad48b99ffb *sandfly.ppc64le
EOF
)

# if sshd is configured to use internal-sftp
if [[ $cmd =~ ^internal-sftp$ ]]
then
    /usr/lib/openssh/sftp-server
    exit 0
fi 

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
    $cmd =~ ^echo\ \"DATA_START\ [0-9a-f]{32}\"\ \&\&\ echo\ \"[A-Z_]+=\`\/usr\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/head\ -c\ 6\ \/bin\/ls\|\ \/bin\/tail\ -c\ 1\ \|\ \/bin\/tr\ \"..\"\ \"LB\"\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/head\ -c\ 6\ \/usr\/bin\/ls\|\ \/usr\/bin\/tail\ -c\ 1\ \|\ \/usr\/bin\/tr\ \"..\"\ \"LB\"\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`head\ -c\ 6\ \/bin\/ls\|\ tail\ -c\ 1\ \|\ tr\ \"..\"\ \"LB\"\ 2\>\/dev\/null\`\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
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
