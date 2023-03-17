#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.25 // th(at)bogus.net
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
8fe8b7bc6c8d61051986e2dfc2e45e3bb1dcfef9eb83c727aa896aa9ac000264e74830859593ae4a9e88fae45dd61fb07f371e5d5f10b60d8ba1b34ad9e53f27 *sandfly.386
ae75b8daf4485ed26ba66077b8a366afe7aeb4868b55f6ac729001f8b9686e308240e768bfd5a75b963484a13850a4df16f41476d9b7a5698f019a08de888b78 *sandfly.amd64
fca83325c5a1aeec1bf2f3163bad46c10ed385b2af61562630e4fa4efb134550ce36d154be474991d68092e8a62c0f4ea4f4a97ec686125f7f6e161038d4b6e5 *sandfly.arm
fca83325c5a1aeec1bf2f3163bad46c10ed385b2af61562630e4fa4efb134550ce36d154be474991d68092e8a62c0f4ea4f4a97ec686125f7f6e161038d4b6e5 *sandfly.arm5
ec9b05792822ae96434170f573c643e38fed8b31bc3814220e4341edf07227a17aa7356d3d29de619df0fafc8fa39260205ac8415c1b2ad203423ec55fee98ac *sandfly.arm6
c55aa7543adb6639a083e144af28944eea4efcdc059c4022fb3271542781b6f9ec985a904a5e313685dae47dcdbed20be5282a6b988fc38ec8b93413fba3253b *sandfly.arm64
500d5e80a2411f333134acb433364fb71b897abbed91333b1baefde98c8b2d450e9eaae878c8a7ef2e8d8958d9e2bf30f012eeff4a72922560c084b57f868064 *sandfly.arm7
9b2f6ffceb5b7cd52406218b97f8a5ff37be08d25efb747be7f1d80883655ac3f0a7e5af50449a603cdf812dfb46159ba92a026481f09142d0d56f0fbd17fb3c *sandfly.mips
784ff71293f08f189503a0585e61adcf9c76b2e1c0939272a891c29e5fe5418b8e4d63f24c5fefa0f062142cd5a25155ba4508a1cd1be7edc0c5866ffa49f150 *sandfly.mips64
03e48fe23e3833f4919df0c26680dca85ce8c60ecae1c6e2e7d6a85259772e2cb46c84ed22e4a80c587637b55a110c781be561562adbe0e00c973cf964f5c895 *sandfly.mips64le
9d950a7c20c5fae0bced3c7b999c4fbcddb5ffdfb37236edfbf73b01d9bd42eb3ba17fec9818b39cb089a5f509fd3046547528f90c6f076012c524daf864dfc5 *sandfly.mipsle
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
