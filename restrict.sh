#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.26 // th(at)bogus.net
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
78f9a949dd10aa5edfde26916e1e3e08b5446f27d12b7967a7ddc189e223f5ba00e556bb5435acf2c2ed4c91401d31892d37bcf1331c9f3325df321c2822d580 *sandfly.386
d272e165c3c14986f767a294d8f17286ccc0a4fcd89e1228bc94dd8890d7871bcfc4cdf30e550d1f7e80e63b7c0afc7f61233e2f43e7379b7e0e57d5425a3127 *sandfly.amd64
60835b79604ad8ba8dc7a34191ed61747649bf9abb255fb693897930cf0bda7704b701d33d1d5c5880438f62d53299b61248b819d27bb6fdce1ea664763254c1 *sandfly.arm
60835b79604ad8ba8dc7a34191ed61747649bf9abb255fb693897930cf0bda7704b701d33d1d5c5880438f62d53299b61248b819d27bb6fdce1ea664763254c1 *sandfly.arm5
ec60172454591c28268cdd616922c20f7f5afb0d7aa420f837bd8f0746f0c052fe7809f3f63fd245ab7eec303273ee5dbe32a2ce1ff1b49f763249691690cfb0 *sandfly.arm6
59ad780f7b7b15b091418cc9898c093700c8181fc042c0a5c9db67168a002f3a61c31681c3b7bd27bd3735d0f80d97d8ca65ed6689c0306b4e7ccd8928946fe3 *sandfly.arm64
3843ad70b026997db708e4e7208d91032f52126b785e2fb5875f2efa9419f798db7948ed47397ea48199e94a3c172e0f1c77580496307d38b9fda38321269d32 *sandfly.arm7
392d530aecec761ac0a39bb6764470021eb4dd58da5ef4be899d160bc592319df78bc87ade402a0b8daf6401dd17ecd6cb127b71431955d57dd97c1455765d7e *sandfly.mips
4b89b0b9abab8258db62b4598e619b747d55b91db16a2e62797c5667d08d72f7e889071b05eec55cc5176cdb5fc69a8aba50a9dd4b4fc517662242135ca30b81 *sandfly.mips64
ed00db0a589205bca6953dadf99fd22458b42843c40fc856022fd7537c75bcb647e1d1d8d1801c31580648c70bd68b621ff12767398fa3d82e24e070f8ce2575 *sandfly.mips64le
75dfb190d4986f34ec444780ce93dbe0b08475176caf1fec14162da1e264c2507c9eb923910b63b7dceea13ccf9e3b07a94d2d7a31a9c92e3228a3549cb5582c *sandfly.mipsle
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
