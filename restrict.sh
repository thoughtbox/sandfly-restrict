#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.5.0.0 // th(at)bogus.net
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
b523d0e0b2a5e0539363f41c53bb0875ef330f6b7c0ab2fd9b3b7e3a76584aea7843207e23100b56e78d362962f77c705b05b90047a888b41cb743b7668251d7 *sandfly.386
507027f9a665ec2ff931f5ac77b55927cd34ea84b03bbcfbf2a280d7d5a2ee6b4b5567fae2dc7343253c87e4a2e7ff019e99933b2eb8b0cb613c70a6a4c9517b *sandfly.agents.sha256.txt
ef8627ea8fe45a3263b995e82f4c037ea201f0cf2f078cfec5529e120e38995c5d4bc4a9ff9d058e65278f9d8c0ddc99ae8285c179746e160c3b77a01dd492b1 *sandfly.amd64
33fc60bb79ca7a0790aebd90b7807c70de13e0fb513ead9cacbd26b94b92611ec342bb559d6389d405885dd5d5fe4ab00f77badaecef16ed71dc5f263834e7c6 *sandfly.arm
0edf5948c96d170b1f5b3bbc5790cbc3f28a4c0f927100141b49d6dc77db2f96bb45681dd97af27e7e6e08cba35ba26e0163398359466c7e4ec7eeb382226f2f *sandfly.arm5
d052bde2712b8d6c5fb7fa6c3d5b658ca9a73218a863be859f30f76f5450e8b5df89595bdbd2e9cd4e5856f3725322268a27ec7ae4feeed4496b500a83b51fcb *sandfly.arm6
959d9508a58ff22bd53ed48404e2f9a5f5844cf3f513eb6c71a3a75b535d8cd4c06132a08b2cc6fc21f6d2e5f72957381605823e0c6b49d8d2cdf01fed00291f *sandfly.arm64
0127f66ed752b9a0aee4ecdafd6282a5f05cce8869dc7cb8a73ca8e5230593c2c89a1cc172d27bcd4c9f4f250f67127de90223f963af86b70530d3da09dfc9c4 *sandfly.arm7
47066f4b68334c1dad38740ee15f4d26e3cfb5df4132a217865d9b25c8b6aae0b02c7656a450f5c55277ba33d13ee071c91db3b904ccd52b3f870b9a27619ef4 *sandfly.mips
475e5cb6a12e042b4b7f44ec67fb404d943aacb2824e58783d16c260d21901afadab422cc66421590739440caed7b5a9503911bb3579490d02f4f7ea62aa7527 *sandfly.mips64
74d9b008ed5a2c0be600e2c17aae12c25d232663c46620a2e4d88cb1a15d6ef39adfa1fb7a62e777817010fbb2e30d9f31282b0be26eff3f5f8b6a4f4dc8b2eb *sandfly.mips64le
6812b4ad901ff7fc0c6fb0939342325d53da760001085d3259fc5fc117025b918045fadb0677f8bc81ce18d17dff1b81b98b20382bf71f83471cc6c95295f1ef *sandfly.mipsle
ac71cd8227069d82675da95e558e1ad2f3649716c6522386b40a811c1baeb7b98fc1af377531a48768df5d500f914d3e0da139f618a6a32407369f696d2a8a01 *sandfly.ppc64le
37e7cddd71d8254d9c931b62a0cd6636762d944f692d9a20a6aa5dea1131ea80bca68e8bcd1335c59e0782a3c5d6733283fe5bec268997499b60fafc7876dbf6 *sandfly.s390x
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
