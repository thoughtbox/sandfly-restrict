#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.0.5.3 // th(at)bogus.net
##
## Copyright 2024 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## Change this to your alternative agent binary names, if in use in the Server configuration:
#agentbinarynames="sandfly"
agentbinarynames=$(echo botfly,sandfly | tr "," "|")

## Update this variable to reflect the paths to these external commands:
## cat, basename, logger, sha512sum, awk, tr
PATH="/usr/bin:/bin"

## list of valid hashes (ref. https://github.com/sandflysecurity/sandfly-setup/blob/master/sandfly.agent.sha512.txt);
vhashes512=$(awk '{print $1}' <<EOF
53d9bb2c7b25553bbe628026244a341b671efc11b88838ad3ba0179144dcd6081dc42f68ff241d6540d22b06ea014873d4e96350c0e79402015bb1548f4cfe10 *sandfly.386
d9b6dac2cf09a21ded5089053e56a47a56816597c4ff5f50598f6706f94be2c92223d2d0e08629a74ff1a055f35dfe67aeebac47278f8878b8722c71c7980c59 *sandfly.amd64
207bae4275b160dd58b990398e8efb0d8cf7c9fbe6bee0e1f74ea4c0b1c2aa2a2d12f295bb2b4c05122875c0e00092a870c68dfb9f6143266d6f738bd6fd34c7 *sandfly.arm
e7cf39974cb4959d66ba1a06a5d297eff1169993ffa1030928eab9d0cc6221f9568b9c687e7dfec83f037d6fcef47711a9d7031a4e7ea201fc2521975bd51df8 *sandfly.arm5
9faad2565ee64e2d8bbd34c22fb414a6324e04048645ae2e096c49bc975b914f392da92d1e83079104697b1bd017b3c0e22754d577cefc71a914af3a9779c3ea *sandfly.arm6
6e60f9cd7804190cff609d9ceb8f2caf6a369b3a657d5119e0562134cb6a613c94820d945e4db779cd434dcd9e89fb068eebff4b1fd49ea37e8543999ca02572 *sandfly.arm64
d2b111a20e0248eb9dadd4ca37b1d4cad3b4218a4d5c66383dbfa227090f394d40f9469274d2b287cc86ca9c598ca1f10df019a0ce5ffaf33ec03a3554d6e5e4 *sandfly.arm7
13d80938ff25197a846b776858a714671ecb63b66069704e5129034977b4d43aa057bbcb0f80455e3b353f5e276f420794b7fed8cf99aebd83a2873b06b20b45 *sandfly.mips
3295f1084c7a80ec5dc9be729859f59b543eb54b8c4f2c18c39fd38af40fe7b8040ab19a440fbd87156efd4e3d0dce58d804f7fd06e5ce9be8151c2ceb3ba486 *sandfly.mips64
870cb38138783ac5d026a5606e119a413f6f4d49950b4d9e90da3ddd7f2f40b767889c4a549d2bda0b70ea75956dc67992cf4368d25a9c10142b966c9587a646 *sandfly.mips64le
bf3c5a247bf19b52ba02afefa9c6170bb6a736917a98a367f81733a53ddfbc9418deb8ea1a7562d898eee206d83ac826bdab6085fe2eada4cfa6eb5226cb8777 *sandfly.mipsle
86b57241b087157d973c58cb1cd52cfb8c4164fe48a9d70cefb72e4f2b9e5f3f314249231cd14d0c1f0bf1a2a8222e43311ff24030e4e3bcdd99239663f6145c *sandfly.ppc64le
90bac16c930d869f650cd1d0a03daff79604ff5a5493f30628e5702de67747ff6331d78fe99f1909e27970d3cd4c47e37197205665984d665512d3167a11f707 *sandfly.s390x
EOF
)

cmd="${SSH_ORIGINAL_COMMAND//$'\t'/}"
cmd="${cmd//\| \\$'\n'/| }"
cmd="${cmd//sh \\$'\n'/sh }"
exec_cmd="${cmd// \\ echo/echo}"
cmd="${cmd//; \\/}"

function validate () {
    input=$1
    rex_1="^echo \"[A-Z_]+\"\s*$"
    rex_2="^echo \"[A-Z_]+=\\$\((|/bin/|/usr/bin/)(pwd|id|uname)\s+(|(-u|-m)\s+)2>/dev/null\)\"\s*$"
    rex_3="^echo \"[A-Z_]+=\\$\(which\s+(cat|ls|rm)\s+2>/dev/null\)\"\s*$"
    rex_4="^echo \"[A-Z_]+=\\$\((|/bin/|/usr/bin/)head\s+-c\s+6\s+(|/bin/|/usr/bin/)ls\s*\|\s*(|/bin/|/usr/bin/)tail\s+-c\s+1\s*\|\s*(|/bin/|/usr/bin/)tr\s+\"\\\001\\\002\"\s+\"LB\"\s+2>/dev/null\)\"\s*$"
    rex_5="^mkdir\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s+&&\s+chmod\s+700\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s*$"
    rex_6="^(|/bin/|/usr/bin/)cat\s+>\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+&&\s+chmod\s+500\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s*$"
    rex_7="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+.cd\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s+&&\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+.[-\ a-z0-9]+.\s*$"
    rex_8="^cd\s+.$HOME.\s+&&\s+.(|/bin/|/usr/bin/)ls.\s+-1d\s+(\*/|[ TZ.a-f0-9/]+\s*)$"
    rex_9="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+-x\s+.(|$HOME/)[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s*$"
    rex_10="^LANG=C\s+sudo\s+-S\s+(|/bin/|/usr/bin/)id\s*$"
    rex_11="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..(|/bin/|/usr/bin/|)rm.\s+-rf\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.."
    rex_12="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+...$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+-k\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/sandfly\.pid...\s*$"
    if [[ $input =~ $rex_1 || $input =~ $rex_2 || $input =~ $rex_3 || $input =~ $rex_4 ||$input =~ $rex_5 ||
          $input =~ $rex_6 || $input =~ $rex_7 || $input =~ $rex_8 || $input =~ $rex_9 || $input =~ $rex_10 ||
          $input =~ $rex_11 || $input =~ $rex_12 ]]
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
done <<< "$cmd"

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
                eval "$exec_cmd"
                exit 0
            fi
        done
        logger "$(basename $0) fail: $dir/$agentbinaryname did not pass hash check"
        exit 1
    fi
else
    eval "$exec_cmd"
    exit 0
fi