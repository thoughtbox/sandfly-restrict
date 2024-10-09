#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.2.0.0 // th(at)bogus.net
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
d25b24c65d9c6e9ed508d1a1af1ac5d43c23685579bd7227f24ff8add1ffb5cb06b78d4c282a26478efc24e70d8760ddd86ae01af4779ec4be32a55e0fcdf71f *sandfly.386
a9604b5f514aba796acc768e2b9b4dc2945ef0043773916855ce2f6c7ba41d91840080e0fc192e766331f78e1f162f1dd982182c4caf25b970a7855ccb77359b *sandfly.amd64
d5112d821263db811b87cff76cf8edbf93d9d6f207543f71aa4927ec0cdf5ff46fa0f22fcf323d9d2ecec8f26f769699b4c353166b0331929f58c46497863aa8 *sandfly.arm
8b47b935a68aa01c524a3d2fa7bbec2edaedf63a3bfd032fa609752ee9c25c3417036c739ef5278cf0019d23a782c29b5426a61777d7da49f979e082ea25e6ce *sandfly.arm5
a7d07605fd836771565fce9649e241cfa17a2b9a68a71c3a91bbeb601c9e93ebf101e5ceed14a4a4ee10d8cbbcfd07a6b6de1b220d3dcdc5a9ee1e512d802e54 *sandfly.arm6
7c493fef518d64881c93c3ebdd44e8d1516d27bbb8b746852170f705df39f38c3fc4e692555927f5c09dbd7598d1a5bd069200f8f2d8b330418074fd9ac98927 *sandfly.arm64
bef4779a4de467f8a16a9d718cf229501728116c6d9b4636d4eee4bf12a93b066f9c5c59bfb21b6157bb587c8e768972db5a194c7588229f22d25647945cf43b *sandfly.arm7
9a0fa1856f4f7678fa9a9e6b4c48980fa983f761ccc6a26dd4cb7bac015e85048f8bf140eb4b0c5922d3d7b4a0a66db49b520191f32a6d215ab610cdfe17a6f0 *sandfly.mips
1ad5e99c4b1b8c9286e5b1eadec24acb746acd0b476e6a4ab69f2152994ed4f865d0cc31ffcb7267f8fc0c422858097dca9346fab63ee7e30c616ca54f972f25 *sandfly.mips64
70afe35bac14cb39e5ca8a7d185f42326c36c1cb540100312242c95672a857a0d8d8107ecff74202a26f814fc3d5ebf2ec099958dd4100bae16784e998365cd7 *sandfly.mips64le
e55d84055d2955d85e7abcb8e1447ceaf42d1decac8971cf33bfd7b8c738cb1c0d2677a8df16ebadaeb49e00be9957cf61cfd726c8c55c3eabe710dfbf3b842b *sandfly.mipsle
cb4e95125995a607307e8e742b9f016c8200b3dfb5393e1a0990fb17645bb511bf80c6d77f0a8d7723860af9983533afac73800dde522fed26baa7fab6b1dde5 *sandfly.ppc64le
440a86bd3192f90454350cac299d857dddb6d0152e66eb68d9def9e856ebc7d86967eb6b2d782db8b0dfed19d7ea9d50e4a1e5e8dc80a562548a95a8536ec698 *sandfly.s390x
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