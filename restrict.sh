#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.0.4.2 // th(at)bogus.net
##
## Copyright 2024 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## Change this to your alternative agent binary names, if in use in the Server configuration:
#agentbinarynames="sandfly"
agentbinarynames=$(echo botfly,sandfly | tr "," "|")

## Update this variable to reflect the paths to these external commands:
## cat, basename, logger, sha512sum, awk, sed, tr
PATH="/usr/bin:/bin"

## list of valid hashes (ref. https://github.com/sandflysecurity/sandfly-setup/blob/master/sandfly.agent.sha512.txt);
vhashes512=$(awk '{print $1}' <<EOF
8ed18af92122ccb01fc6c192f5fe5821e91fefe62936bc121cd54b22a868e5e3079c392431fba4bebea3e9e3a5d1bff13475eb8afc24a42ffbf33826b448bf3c *sandfly.386
2dd2e170f22f6c8325d5f01394ef81c8668b312be3d8d419df1a0d1edc3e7afbd8e6bc4f13e8de6c344f40ef20178819c4af301f9754919d42cefb154df8f225 *sandfly.amd64
d86f121ac350b5642f58394dc5ca4b3e1160a320c4651bd39c4d8a200553757caf3afb691c4b4377dea18cbc7a716322c05ad7233157ff71a2e70eee93d1546e *sandfly.arm
97f05ddd602c7ea3ae5aadbac216360b43771a0bc037f6632318d625b9e5bc00c6651dc3815211a205caa690d609ecfc4131474d1b36ba29a070d1f527309eb0 *sandfly.arm5
b46e2a41cec0c59c196070f0ec195527616e38cbd6887d905ea72cd573e0a99e9cd2602e211d5ab47d0a95026e12e7c4807917f0f7ae88e52fe61d8ea4aeb40c *sandfly.arm6
0baf60fef7b743f405d3acb8eb77ee5d01c3527c4ae4f5e109a110c4b1e7badfd1720799aeb775ab179fa1615710e54f520e76763c939e12da819e3a6382966a *sandfly.arm64
d86f121ac350b5642f58394dc5ca4b3e1160a320c4651bd39c4d8a200553757caf3afb691c4b4377dea18cbc7a716322c05ad7233157ff71a2e70eee93d1546e *sandfly.arm7
fe4a51cd773ff0b280384b2bc4fed125b80a508b8b3392012421f36e2aeccc60df85f17f649133866915788788a6386d06a267c77f5c9d0bc7b0b5b5c92ee1cf *sandfly.mips
22006536a6b65c4e22f76b69ddcf759e1dd7f493d57771800ff595a456e88f2690e7c719f0cd6fccf4cc040008ed452794436afff0df6a9c97dc873b4d2a6905 *sandfly.mips64
e2f9f81e2401b6cd61b9ceef231b5d6840856c6d859b699d40d3bb0653721305f1f4f180d77a146ca2807b84d79765be8f583ffc9f0206dd974986f939fef6e8 *sandfly.mips64le
f6029669ee62c3434fc4fe4902caab145112a02a1271545e227d12b5820aadb4a63da5d4495299bc1795f00617c5c7fbe23db4c1b8cfa76f349a823d8c0d7449 *sandfly.mipsle
5abab102c6e6c7a20a25b20f49627802625fbfae6bd395be997c015ea48f52b69d164397c257f6fe3f70e09dc1e78b26d2160ae18cf240796e84e9c743fc3dd7 *sandfly.ppc64le
EOF
)

## (I know, now I have two problems.)
cmd=$(cat <<< "$SSH_ORIGINAL_COMMAND" | sed 's/\t//g' | sed 's/| \\/|/g' | sed 's/sh \\/sh/g')
exec_cmd=$(echo $cmd | sed 's/ \\ echo/echo/g')
cmd=$(echo $cmd | tr ';' '\n' | sed 's/ \\ /\n/g')

function validate () {
    input=$1
    rex_1="^echo \"[A-Z_]+\"\s*$"
    rex_2="^echo \"[A-Z_]+=\\$\((|/bin/|/usr/bin/)(pwd|id|uname)\s+(|(-u|-m)\s+)2>/dev/null\)\"\s*$"
    rex_3="^echo \"[A-Z_]+=\\$\(which\s+(cat|ls|rm)\s+2>/dev/null\)\"\s*$"
    rex_4="^echo \"[A-Z_]+=\\$\((|/bin/|/usr/bin/)head\s+-c\s+6\s+(|/bin/|/usr/bin/)ls\s*\|\s*(|/bin/|/usr/bin/)tail\s+-c\s+1\s*\|\s*(|/bin/|/usr/bin/)tr\s+\"\\\001\\\002\"\s+\"LB\"\s+2>/dev/null\)\"\s*$"
    rex_5="^mkdir\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s+&&\s+chmod\s+700\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s*$"
    rex_6="^(|/bin/|/usr/bin/)cat\s+>\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+&&\s+chmod\s+500\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s*$"
    rex_7="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+.cd\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s+&&\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+.[-\ a-z0-9]+.\s*$"
    rex_8="^cd\s+.$HOME.\s+&&\s+.(|/bin/|/usr/bin/)ls.\s+-1d\s+[ TZ.a-f0-9/]+\s*$"
    rex_9="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+-x\s+.(|$HOME/)[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s*$"
    rex_10="^LANG=C\s+sudo\s+-S\s+(|/bin/|/usr/bin/)id\s*$"
    rex_11="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..(|/bin/|/usr/bin/|)rm.\s+-rf\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.."
    if [[ $input =~ $rex_1 || $input =~ $rex_2 || $input =~ $rex_3 || $input =~ $rex_4 ||$input =~ $rex_5 ||
          $input =~ $rex_6 || $input =~ $rex_7 || $input =~ $rex_8 || $input =~ $rex_9 || $input =~ $rex_10 ||
          $input =~ $rex_11 ]]
    then
        :
    else
        logger "$(basename $0) fail: input did not pass command whitelist"
        exit 1
    fi
}

while IFS= read -r line
do
    if [[ ! $line == "" ]]; then
        validate "$line"
    fi
done <<< $cmd

if [[ $cmd =~ sudo.*($HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16})/($agentbinarynames) ]]
then
    dir=${BASH_REMATCH[1]}
    agentbinaryname=${BASH_REMATCH[2]}
    if [[ $(sha512sum $dir/$agentbinaryname) =~ ^([0-9a-f]{128}).*$ ]]
    then
        checksumhash=${BASH_REMATCH[1]}
        for hash in $vhashes512
        do
            if [[ $hash == $checksumhash ]]
            then
                eval $exec_cmd
                exit 0
            fi
        done
        logger "$(basename $0) fail: $dir/$agentbinaryname did not pass hash check"
        exit 1
    fi
else
    eval $exec_cmd
    exit 0
fi