#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.5.1.0 // th(at)bogus.net
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
9d522de2f11b06d8c247b830c115cf84f10c206875189ff3bdf17002d8bbe9ba68ebcb5cf192ccefb5a1c29b16c411cdb909c58adacf195af63404d297f44ea7 *sandfly.386
baae9b6b9def7a8510d4004b60bed693cf363990b5839c0a3f456297ae47bc053b1e9aa3de89e748d1fc696b0f0dca5debecfc30cfbc7e584baf6ad5fb9d27d0 *sandfly.agents.sha256.txt
7f3661b3b7f66e49c29dd9ebf7188bbc67ed9a6520b0d6b744ec59ad8d19e2325ac7887afb4462ab08a3370e82454ce9f3099bb539c8904b06b9cd8c1edf0eb0 *sandfly.amd64
e8298317e0c7ba589d239ca710a89166ea3d5a320cd5793a018c99e47337a816ae74959cad9b0c6f2f7a609040ad1365ae5928c853666eb948cc647b6eb432a4 *sandfly.arm
dcd96a5dd00e1d851c70965e86311c6d45214e5ae75d2ba394b20cf71309e638f260d4fba6d4aec6f30d0708bc47ec3e703e94931427fa36569ad4e0d97634a4 *sandfly.arm5
5e88a2b289aa0a49b2b2e0c8ab9cf01394f5cb4614278bf9ff53d97fca342a83dc70909acb1f9104c0d56a9b9738832bd0811206935831a53a1922fcc87f94b5 *sandfly.arm6
9cda6df43d47b0352836bad51626e88ea2aa07b5165f3b109eb4f48b737d55b0c6bd0726afb225c64f7258f0615f4fa9c50066054a1fbe3ef61c8c9287253dbf *sandfly.arm64
7daac48b9bc5bcfac44682deb181269cc828b9a2e5879712c73119bb08770d85b00bc8513ff787052da47d48568bb939459e567aa90a006f18e70817a5579d74 *sandfly.arm7
ff7179ed816943cf378efd88f4d3e1546e57137a56bc1ca7abd1133b7623ad79fc3769ba92a95c24036fba27283343857540bfaf9717ada5fc7db3bd07eac5dd *sandfly.mips
5333cae0ecd8c87d10c67333e1086d7f1f078ec301f1c0971854b2c13bb58f32f62c6a959b211ea26d2bd3f20400234be9299cfc90d6c8cfbe9fdb6bc0b8ef42 *sandfly.mips64
bf5a0ac83ba5ebac1821b72f4552e683fae281c2d8f3c3ba33c7d839e701603f79020462d89cf1b83a81c4746ec8b2705bc3e6197e049b4d4bb7a4fce04e511b *sandfly.mips64le
bb7fc3a3326a6e8b745d15fd78ac91922b0beb138801e6bb4d7c57ab912b9dbb2e8811ce44d4eb9bb4e9210b7bec85790c2302f34f8ed74e6275a0368f858b2b *sandfly.mipsle
d57be358962b1a47e015e93f48bab3d16f6281551459b18213c97aefeffbc9284d61ed54077e2b6b60c4e34e29bfe50aa911e74d0b850ff4aa1972955ddd152d *sandfly.ppc64le
88381c53487db2e1243f965816aa3d7f6d869e92fe6d4a4af7ccd90d61fbb4f428e1dd8e1ce6e4a950b6782c49a8ca784cc8928d39e3bfc6c6f655b0e9479a1c *sandfly.s390x
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
