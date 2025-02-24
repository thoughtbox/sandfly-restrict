#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.3.1.0 // th(at)bogus.net
##
## Copyright 2024-2025 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## Change this to your alternative agent binary names, if in use in the Server configuration:
#agentbinarynames="sandfly"
agentbinarynames=$(echo botfly,sandfly | tr "," "|")

## Update this variable to reflect the paths to these external commands:
## cat, basename, logger, sha512sum, awk, tr
PATH="/usr/bin:/bin"

## list of valid hashes (ref. https://github.com/sandflysecurity/sandfly-setup/blob/master/sandfly.agent.sha512.txt);
vhashes512=$(awk '{print $1}' <<EOF
9d52acfc445c24663af454d16b2431608f8fdfcc289eff45e0a984e2c12be4a2ebbc11d3a07f4d02c58efb18a194505a7aaee4ddeabbe8dc23a7a2fafa283e18 *sandfly.386
124ab50e270c389dcbf202e2f96a60740b064562e4d12b18afb234f340992cdec4e4ee34171c2ee83916d63c7eecba78da1205ac89e30bd3b0870d8754188c29 *sandfly.amd64
b45bd823dfadbbae3b1be5ba1114641f60dabb177dbe4ac7b53e269d4bd1036e81908f9f117f0022663be4acf5abe1c209db3d0588076a02da35cae211c7f44e *sandfly.arm
f4d87787123aa54d503a6acba3fb37e9cd429e5627d1807fe02f4549c65157d69bf1218c6a0da6a3bbbb6391e93249ad29569c457a2f4980a6792ec10446d69b *sandfly.arm5
8071b8d8ef81b35c6411df79fe4ac62ca0f6ac0bfad3ce4ab3a99ad421d15f5bbd20614d1177976d8f1c5eb6009f5f541d81823e7b86f87ca4c8e19c69a6ffeb *sandfly.arm6
a9511b64f4a9731f1320a0d58e755ee09c77e4abb17308c938ac19079dc6dbabf6f7db68d45e7240628f5250fa57a846809bb1899b294caf7ea51947e6421e39 *sandfly.arm64
6ee9a0285e7afabe66be50101bc8660d1e3adc10b803d7da7c3d78b882a4f3e641b41af8167686e5a62ae9dd321ab84f0b6c8d9a0f752a124e3d922dd8c86947 *sandfly.arm7
26c91479471e8c6529fb8863380069ad996c85c5003fb83497d97811df623ee45f21770eb0ed3507ca355a7cd07c2558f376f65696fc0b1776fbaf6d6935cfef *sandfly.mips
a85fad394832ab608539b4dbbb693d3f7bee644f30a773e2a673e3f53c4c0886766f449e4b8dc0dfa8ec39a8122f011a61818c8d66de3efcafc96022b5467d1b *sandfly.mips64
a9364b0f4bc0e7ed2457d51d5dbb9a07197924fdcaa7c71ab3d93c2d19cc61358559e4cc92a68656293c2732ea843c71a6de5e2d687f9118093186fe080a1934 *sandfly.mips64le
fcd7816a0dc62dfa2147db6935cd1f322e8a130815017522a3dc205dc1ced4f2b9d85b81e517601bfb1210f75260877e10058bcfd287f24459042ad45d96ca58 *sandfly.mipsle
ac076f68e15425359d6b231a52c7c20821d576d46785d9cee01e022563118b0f3ea7e56ab654c1f1333719ee479a9f505bbe25551a3580025db165be7e904fe8 *sandfly.ppc64le
bd4c7ca1cb7bb5c8e6a634065d042be1dcbca33bea86a3e16aa5e2719de5e91fe7e5044dbf61a6e9b9e01876fd290323be02c28756ea08182321bf2d5c7bb46b *sandfly.s390x
EOF
)

cmd="${SSH_ORIGINAL_COMMAND//$'\t'/}" 
cmd="${cmd//\| \\$'\n'/| }" 
exec_cmd="${cmd}"
cmd="${cmd//; \\/}"
cmd="${cmd//sh \\$'\n'/sh }"

function validate () {
    local input="$1"
    local regexes=(
        "^echo\s+\"[A-Z_]+\"\s*$"
        "^echo\s+\"[A-Z_]+=\\$\((|/bin/|/usr/bin/)(pwd|id|uname)\s+(|(-u|-m)\s+)2>/dev/null\)\"\s*$"
        "^echo\s+\"OS_BITS_[A-Z_]+=\\$\((|/bin/|/usr/bin/)head\s+-c\s*5\s+(|/bin/|/usr/bin/)(env|ls)\s+2>/dev/null\s*\|\s*(|/bin/|/usr/bin/)tail\s+-c\s*1\s+2>/dev/null\s*\|\s*(|/bin/|/usr/bin/)tr\s+\"\\\001\\\002\"\s+\"36\"\s+2>/dev/null\)\"\s*$"
        "^echo\s+\"OS_ENDIAN_[A-Z_]+=\\$\((|/bin/|/usr/bin/)head\s+-c\s*6\s+(|/bin/|/usr/bin/)(env|ls)\s+2>/dev/null\s*\|\s*(|/bin/|/usr/bin/)tail\s+-c\s*1\s+2>/dev/null\s*\|\s*(|/bin/|/usr/bin/)tr\s+\"\\\001\\\002\"\s+\"LB\"\s+2>/dev/null)\"\s*$"
        "^echo\s+\"[A-Z_]+=\\$\(if\s+\[\s+-x\s+/usr/bin/(cat|ls|rm)\s+\];\s*then\s+echo\s+'/usr/bin/(cat|ls|rm)'\s*$"
        "^elif\s+\[\s+-x\s+/bin/cat\s+\];\s*then\s+echo\s+'/bin/cat'\s*$"
        "^else\s+echo\s+'cat';\s*fi\)\"\s*$"
        "^elif\s+\[\s+-x\s+/bin/(ls|rm)\s+\];\s*then\s+echo\s+'/bin/(ls|rm)';\s*else\s+echo\s+'(ls|rm)';\s*fi\s*\)\"\s*$"
        "^echo\s+\"[A-Z_]+=\\$\(if\s+\[\s+-x\s+/usr/bin/sudo\s+\]\s*$"
        "^then\s+echo\s+'/usr/bin/sudo'\s*$"
        "^elif\s+\[\s+-x\s+/bin/sudo\s+\];\s*then\s+echo\s+'/bin/sudo'\s*$"
        "^elif\s+\[\s+-x\s+/usr/local/bin/sudo\s+\]\s*$"
        "^then\s+echo\s+'/usr/local/bin/sudo';\s*fi\)\"\s*$"
        "^mkdir\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s+&&\s+chmod\s+700\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s*$"
        "^(|/bin/|/usr/bin/)cat\s+>\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+&&\s+chmod\s+500\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+.cd\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s+&&\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+.[-\ a-z0-9]+.\s*$"
        "^cd\s+.$HOME.\s+&&\s+.(|/bin/|/usr/bin/)ls.\s+-1d\s+([ TZ.a-f0-9/]+|\*/)\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+-x\s+.(|$HOME/)[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+(|/bin/|/usr/bin/)id\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..(|/bin/|/usr/bin/|)rm.\s+-rf\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.."
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+...$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+-k\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)\.pid...\s*$"
    )
    for rex in "${regexes[@]}"; do
        if [[ $input =~ $rex ]]; then
            return 0
        fi
    done
    return 1
}

while IFS= read -r line
do
    if [[ ! $line == "" ]]; then
        validate "$line"
        if [[ $? -eq 1 ]]; then
            logger "$(basename $0) fail: input did not pass command whitelist"
            exit 1
        fi
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