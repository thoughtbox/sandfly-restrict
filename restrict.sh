#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 1.41.1 // th(at)bogus.net
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
5f713487797ca4b9b0344763fd35af90d108e9408803041a0f7f98b35f70631dedc1a2162f566462733a06b16750d527bdbc77bf843cf10cfab143a629258e66 *sandfly.386
8ffb03315e8090591b36607c36f06510e1ceb3833b90478b744254450f4045b55bef917700a60f532ea5938cf844d6f21f5dc647d38f0cdf9a14905ca4b1ee95 *sandfly.386
a9ef433eecb7489322d2bd0a27237b7f0984d96af6eb937b90ac0a46207a80c8e3025faf158453c504905a948af701696278a11aefa92ff48e423da1bfa37825 *sandfly.amd64
ba64bb1fdd32c24e945a204f29b61c6c2e779856036ac963e68dce21f2a812b68e6a18f0874b227e39f084805522d3ad87163bd580d5bd36ca0b65794f2c2f1a *sandfly.amd64
593d4aec5831de449cbce740b2c297ab414f7dd22b3556337a962d46999b6145712432e3af2acdfaa7920ec4ca9b5ece9175eab5a99072847efcabde8ac22879 *sandfly.arm
91471e4724fb235bf8e7bde66fbf0acb67bfa103564ba55b286d8565ef8ca9d7ca8e7b3805197f2e33c41cbb680c1771444b1297bae0b3a6b96dfa877bb5784e *sandfly.arm5
1d2fd70ab639fa6980b3bad23877c0c656d6d9898339532a5838c28d57d64d05107559077231b7f00a8652f61a9e96e2ee2e878f767c9d596fff279ffb8b05ca *sandfly.arm6
120a01d1dc1c6bfbf0b3d8741f3074b15d1665ff42bae851c2b6a1fac9523dfff0927fad89f3d61863f7fe26134d40e5378d35140eff773b9b54baaa67b6e5ab *sandfly.arm64
a2816ba2adc480ae9040f37ee79c73432ab5bc76d10dad059eb073f0346e0e9c21291a2197a5ae25aafac35d079e87255601a08f188bf9ede6163fa96ecc161c *sandfly.arm64
593d4aec5831de449cbce740b2c297ab414f7dd22b3556337a962d46999b6145712432e3af2acdfaa7920ec4ca9b5ece9175eab5a99072847efcabde8ac22879 *sandfly.arm7
a6cd566e6ba6d9e623222189f43752bca5836149b40f540fa089c237b76c6449d943334b3e0ea46b817c5f96dc730fbe2c6be697d63c40e69a05ce8e0c3c6dd5 *sandfly.mips
c29c7d8d2edb2239776bfbde75d6d29311987e708ad42b6ad06768f8560f67a2cc6e263dcaaf0079be08ab436c23318e0d43402e1aedcedd189f1648be2dd723 *sandfly.mips64
f2b2bed16a115cf6c9377afb82ab7dcedef8988d018342814c89a2faff1d39a3064faa78478bf49245914bba9c6a9f32bb11050e3175c74c6504f85c656de9a3 *sandfly.mips64le
779182b1633a931803f1b44e710fb693b4204e67c404545cc3dd84036a9ab66c33c6dd9a7c5ea83dc5b8f5141208f8875e5a5b5ee18b46b64e7b810909461bce *sandfly.mipsle
6363ba52b33bf1a48e5e315161dcc2b9e655f6e4d62f1dab2dd0ca2fef39465392f69516359b62f0efcc2ee63b67a74b26bb57bd211cabf687034343a418ec37 *sandfly.ppc64le
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
    $cmd =~ ^LANG=C\ \&\&\ export\ LANG\ \&\&\ echo\ \"DATA_START\ [0-9a-f]{32}\"\ \&\&\ echo\ \"[A-Z_]+=\`\/usr\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`id\ -u\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`uname\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`uname\ -m\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`pwd\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/bin\/head\ -c\ 6\ \/bin\/ls\|\ \/bin\/tail\ -c\ 1\ \|\ \/bin\/tr\ \"..\"\ \"LB\"\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`\/usr\/bin\/head\ -c\ 6\ \/usr\/bin\/ls\|\ \/usr\/bin\/tail\ -c\ 1\ \|\ \/usr\/bin\/tr\ \"..\"\ \"LB\"\ 2\>\/dev\/null\`\"\;echo\ \"[A-Z_]+=\`head\ -c\ 6\ \/bin\/ls\|\ tail\ -c\ 1\ \|\ tr\ \"..\"\ \"LB\"\ 2\>\/dev\/null\`\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^LANG=C\ \&\&\ export\ LANG\ \&\&\ echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ LANG=C\ sudo\ -S\ LANG=C\ \/bin\/sh\ -c\ \"(|\/usr\/bin\/|\/bin\/)id\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^LANG=C\ \&\&\ export\ LANG\ \&\&\ echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ LANG=C\ sudo\ -S\ LANG=C\ \/bin\/sh\ -c\ \"cd\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\;\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/(${agentbinarynames})\ [-\ a-z0-9]+\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^LANG=C\ \&\&\ export\ LANG\ \&\&\ echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ LANG=C\ sudo\ -S\ LANG=C\ \/bin\/sh\ -c\ \"$HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/(${agentbinarynames})\ -k\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/sandfly.pid\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
    $cmd =~ ^LANG=C\ \&\&\ export\ LANG\ \&\&\ echo\ \"DATA_START\ [a-f0-9]{32}\"\ \&\&\ LANG=C\ sudo\ -S\ \LANG=C\ \/bin\/sh\ -c\ \"$HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\/(${agentbinarynames})\ -x\ $HOME\/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\"\ \&\&\ echo\ \"DATA_END\ [a-f0-9]{32}\"$ || \
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
