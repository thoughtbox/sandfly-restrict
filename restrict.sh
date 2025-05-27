#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.4.2.0 // th(at)bogus.net
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
17b251c0327424de917409c6137b40175b85a69019f01f44d8fac186c8163b216546a553ffa052ada105d38bf915b2492165191dd899377f4ae7fd32e8ae459f *sandfly.386
d09ab52c905529d4fb797d98db153cc659458b4ebc8c5f58b4f6ebb21a6a89431710837bed5d2e29017fc83d98a3515e96535a4f1687bdac3bc201eaff0cefd6 *sandfly.agents.sha256.txt
9f99f895b1cb7b049495d096017a6534b4234f91052f7a319601fcb5933307fdf519c648f4ec46a59a326c1dd41f631fa5c29336d77105a9502fd88943349a0f *sandfly.amd64
75fa907e0d53ffa6c5f4e12b4a7431850c715c2dcb39851bfa00bd5ae52d83c72435dd5e3ac05c44ffe3e1df2846a2b67a04b04cfc325612c61c79887a290b4f *sandfly.arm
727736411176b355cf193c12c6a3701d3b7d84ddaf800f2bdb28e1fc694f25e32a888274153e36dfa7a7fefc5e29b4cd15aa8d59d085ed96734487507fe23f9f *sandfly.arm5
bfa930b699f79d0fe9725f58b2aa94814d16ae968b4f075f4aa2f83b983e9c666cfda3910a19f2caf0cce86f442dff91e2d15e28deb364efcbbcca0e88bb99be *sandfly.arm6
972a86ced21730d50bd99c1823056fd1c0a66aa29dca0eb43bf029fa9c98f7c0049b77062030e4fe8a8b9adad2cee267638d980713d163dc849697e77c366748 *sandfly.arm64
fb58c1524127f2e0e5ccdd73900506d474b31ffe34bce34df59ea2b4af62f09318c2d0fee6adfff3e28b510929224443923d696eeaf8dd9333aa2a39dd1e37cc *sandfly.arm7
b5d0553f274491c6e90c55166c62b8db0a9e721a6cd54b14242f7301a6b3ff62aa43809bdc9e7950e0e988d6d5b617661e68ddd0ba3b8ea53699a6dd919ccfad *sandfly.mips
8bc648131c5bf3aa9adf43d5852a87142c3aa8b350120d89175c73bae360879c869296e7bf4ed5bb7c1b264d0152529e57389683459a6330889870751c0abd87 *sandfly.mips64
977d0fc06c98aa116f76b90fdff0c5e0b132828e72836f4d0ee1c32300aabceec0162f3ae0bd3ff533a56cfdf1fb26d1cd87cb59eab5a03e4f8f6a57cc6ccbae *sandfly.mips64le
abdfb3f9b0d123f1c87e35c034a9dd56b237a1ca7f48e95f9b9b093612d388284245ab8402e9b9cad4aaec5ed3144803fb928209ae3feb742bd4251985f06314 *sandfly.mipsle
688c57ea443e9bf3650177fc5afe19ad045ead5509410859aa774efa591abb3387dd7da11046da836240bd1398cef1ccf666603b6b0c7b9dae7e7e1a35609407 *sandfly.ppc64le
3c2b1123c29341934efbf72a949783549d9a39c6ffc5ed8f460b2c14b53a564720f6ec0fccd21b5e97d1c4b06a383d151bcbb8f3d14a9ef97270155ff5dd247d *sandfly.s390x
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
        "^echo\s+\"[A-Z_]+=\\$\(if\s+\[\s+-x\s+/usr/bin/(cat|ls|rm|setfattr)\s+\];\s*then\s+echo\s+'/usr/bin/(cat|ls|rm|setfattr)'\s*$"
        "^elif\s+\[\s+-x\s+/bin/cat\s+\];\s*then\s+echo\s+'/bin/cat'\s*$"
        "^else\s+echo\s+'cat';\s*fi\)\"\s*$"
        "^elif\s+\[\s+-x\s+/bin/(ls|rm|setfattr)\s+\];\s*then\s+echo\s+'/bin/(ls|rm|setfattr)';\s*else\s+echo\s+'(ls|rm|setfattr)';\s*fi\s*\)\"\s*$"
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
