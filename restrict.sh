#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.3.0.0 // th(at)bogus.net
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
250c6a9e07c85f036ef44ee2876248a02f7e48137a1c3224a6948678aafebefacc24312f86122f374b1a4c321e22ff412918a1777d43f9ba8a7171b0d88cd928 *sandfly.386
3c665c00d32665350b35c21356444f4ac28a7b2c94a8a22cbcc9193b22813c329713fb6017531123987bc9477627fadb0556a7307747ee3de129b864b7ab832f *sandfly.amd64
a60e333a8262ce73e32bcc7728fd7b5e653878721a93fe95918c200fc6647503d71719d68ede31d2a84cd342302fa959f5152c529c3585476193bcd9ff8fb120 *sandfly.arm
9191c078db5f7d1110f9f822a169a4b623a44403a87c541bcea5bcbd0cbb4b274d94acceac7628a5305578ca02bde3792b34930cd534dfee20f3cdbd7c1f912a *sandfly.arm5
4613dde090c80d1e5e1b8b9c4c1f62960076cfef20d7776a11091be7c7427d807c761dfefa4e89806b7f2586fffa2e094245aadad13633f6c256a43ffcd6b9ac *sandfly.arm6
0367f1fde9f0b875d19b908973c16b6c6a0b75c9c82b611c43e32e833b3714a58ab61a04d3e9fda11500cccad1656a2551d4e2518efff783df6b1104bcc97266 *sandfly.arm64
0cb079ef9d36ac83e8e7803188d62553964f856dde54e85af783db140161281ed988cd5c5955aa8d306215c6561a9c5971158ff7b9c35483b6d7555806ba83d4 *sandfly.arm7
ba865ff28142f6160ef275c26b6ea9f7ee8d24ac90dfc6551906a7da48f147c80d05bd292ec880f6bf7b25d615416af6e949b6b9f68605401300cfc4d7088afe *sandfly.mips
c073c2459e6cb40a5bfd4a212e0ec02f634b29018bd5c5ea5aa6e91d816b16968521e34809bdf4fa28fd59a2dce849841815d60f227f56e44725f901185e5465 *sandfly.mips64
a0df6979d09b0551f40ba467838850cadec92a2f742c265a6931521decfebde0953ed90a5be9fdf2756edcad23f0b2cacf9723230230718356601c7ec71d91c0 *sandfly.mips64le
765b57d134f891599f68338825e12674e726fe43810e31fd138acae84eb815f3b29cfd5174b4665323726c9efbf2c576bae76960ca8a2cc59c160e3d8291069d *sandfly.mipsle
38ec32fdd3a9e95569860add3af00b6e30815f32895bcf21a43da53ae33c653ce2b54878059b56c96a7f2926ea725e3eea23d5b008a928aea35e910ce78b3844 *sandfly.ppc64le
fd62302f4e9f7a63c08bc3c10fe01b0e183cbf548f714f43d91eedfb9308d50610740e3744b1f0a80f38171b588e4c79839013b73746b5b1c3b15f92a5be494a *sandfly.s390x
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