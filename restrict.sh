#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.30 // th(at)bogus.net
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
156e5cd31815bf3e047af9f1afe5059ccf8438758995a9d62398294b0e640412c6dcbab60a8ff4ca45aca7d64b92274310b765d74235f52ff0a1ebeadea41d59 *sandfly.386
f7f8f0ed808d47cf14bb24e92c1c32a360934c59e3408c07d12c139fa9fd53e3ba766f6bbd69473e5761a7db5e443eb582ba0fd7ff259ad08e3495624b90db4d *sandfly.amd64
173d404f3c52dfac5d7c0981ec554061f8caec6cb15985d7e957568e6af5b0a34425df6c28c9de64ed0657e39b92c0bf8748f9e327ff346b071fc4cbcba720f0 *sandfly.arm
173d404f3c52dfac5d7c0981ec554061f8caec6cb15985d7e957568e6af5b0a34425df6c28c9de64ed0657e39b92c0bf8748f9e327ff346b071fc4cbcba720f0 *sandfly.arm5
545ae0db72d8cb886c7300cace253c3cb118a093338f0bb8a2d2d25f6e99c4ce71ddc29ee3a556c3a5e404546411b1bc2c20e61d6704049cdd8ccdb8fcce6b8e *sandfly.arm6
ece84bbbd9c16120547867d168578eaa8a872656df68f19b4272b544712e707a182be17c59f87e8de00012db7aa84f393c7ce9a2c3a771bf4b6dd1e663a1b281 *sandfly.arm64
55a408fda606bb3cc711dc921ab64a101f68bbf0c7c437ba04303d3d1ce0ff6262d7207aa0adc7d7c84b1bcb82493fbe5eb46b6c15875d83e53513f9600adf8f *sandfly.arm7
17007ee22cdbda23795b29c3cda7ca2381d21395e3ba76022e613bdc874a6b09c5e7d4f15f88fe7823d37db9f049b4288dbac97e5d65fdc1055bd41d21986b9e *sandfly.mips
adcbb6c59c8bbe8f4be2316c6422bb12190ce704f0a75af278d46e64ff72a83eacd92fa6bbb4d8d32a8b49e57284e8d910668675f6a6491d169f2dc7ee356617 *sandfly.mips64
9d17eafece8e6e4944b10a20a4e4c73c197c3e0caa5f01f4bd74680c250f9efd038e9ac30d325f1d6520d2348fed047e43dcf279f9175c485c9f83498dab2e49 *sandfly.mips64le
b8e28db2ba003e562c7e355f19404aa9a5fe31143d3e3d48d60f4e4bcd29e6c23a102f88197b21345887f8058edfa03487fa78498a46bfc80982fc3bb060f662 *sandfly.mipsle
74fab3b9a559826ff45e24b4affada368349236708e2bdeb2210c8413c5223676cb91bfe0d0593808e9f2baa55dda49895c0370b242601944c1c7e8513c75b43 *sandfly.ppc64le
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
