#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.7.0 // th(at)bogus.net
##
## Copyright 2024-2026 Tor Houghton // released under the Simplified 2-Clause BSD Licence (https://opensource.org/licenses/BSD-2-Clause)
##
## Change this to your alternative agent binary names, if in use in the Server configuration:
#agentbinarynames="sandfly"
agentbinarynames=$(echo botfly,sandfly | tr "," "|")

## Update this variable to reflect the paths to these external commands:
## cat, basename, logger, sha512sum, awk, tr
PATH="/usr/bin:/bin"

## list of valid hashes (ref. https://github.com/sandflysecurity/sandfly-setup/blob/master/sandfly.agent.sha512.txt);
vhashes512=$(awk '{print $1}' <<EOF
80d5250b651d25662030a3323ee23763bf3b3a8ff5411c315d23745cbaba34dd204acb746e18439277a27183f2abcfc5702a45cf0ace59c4fdf2b6bca780c56c  sandfly.386
1638268afc8efca29ffa81154745b4bda685db3f52c35605ab915d60d7fafb93c7f19f211372abc84d9e2685714c84e7dd6ad28152ea683150f86d2676663f14  sandfly.amd64
6bf72af1eaf605bf1e130390db3e7ff413a2567f173e3858c94fb2a917a301dc878d87dae2897c492249b080ebec0e4ae5ed651906299efd5918b1ff781ee675  sandfly.arm
3756ce07d240ff05268ec59de8a2fa588d94152d417f92fdce18923e3b2b257f3f4698c1497aadbaed1c473309b9ae7df477365f3ffcfd765926aeb1d4dc6115  sandfly.arm5
e41c96e4aa99ce8eed63c396128817937cc39ad1164c028d12a3dfbcd2ec2c643aca391b7e6900b73c6726d6f44bbe59382666c4475ecb139aa3717f8169ba9f  sandfly.arm6
aa7b88e99c7070e02ce2d878aff8b322b791ece8d239d4a1af8656fe6da0e7070d10820489f32bcf15036d09b690bb0e221dcffdc5d0e643af098b70bed11016  sandfly.arm64
e352e3f4063c8d0c89feb16d3e4623acd91a90fea27e32a4baab507792dca70e66fd2ea2845f01fc5a9b1189b25f614bf91deba9b4c33c0a100f1163c7359d07  sandfly.arm7
889cbcbff3e3c7f4b969267973f923a4ea54dabd2bbb258c81bf223fff7637f9d8b8c0e76b6c670649716473889eef4675333855705c0e353d774b7e214576ae  sandfly.mips
d4153f760c0cfb60019b640545a99a143f59d2c667d0f677ffbd337ae8c7240001ac00a24924720833050e1d6f8f5f706acb51a44cc94aa69dfcfbf34b845b1b  sandfly.mips64
4605fda5ccbe936e8ca01fe1ae274a9f4c300b1f612507e84fedf2076e7752d2d183a4d57b88d67107645ae835f64783f392caf5b4390fd47c1b6a7fc654bbbb  sandfly.mips64le
1040f6f2eaadc3958a2783b5ffce8f8bd5bba71a6240ca1a05ebb1d50d4a5956df4cc0dd09fcd8d0f4dc2f708d236f036ba9d7ead9f15522c32cbde62d920321  sandfly.mipsle
f698a0130c3bb5ae6930eea009ea0b80f8943c2c155484166e122847f9f6a59c6f8b0f3dc135d1a9292aad332f2e822cfcea0893fd9235eece6856bf61eb8be2  sandfly.ppc64le
98c47998d603bb049e27677ba7444848f899e99eb5a656b37807c933c69e7369213bf05a734bbfd2654915d0880bf918211a4457fb628d6c22183c6cefefe4b3  sandfly.s390x
EOF
)

function osprobe () {
    echo "OS_BEGIN_DATA"; \
    echo "OS_UID_USR_BIN=$(/usr/bin/id -u 2>/dev/null)"; \
    echo "OS_UID_BIN=$(/bin/id -u 2>/dev/null)"; \
    echo "OS_UID_ONLY=$(id -u 2>/dev/null)"; \
    echo "OS_SYSTEM_UNAME_BIN=$(/bin/uname 2>/dev/null)"; \
    echo "OS_SYSTEM_UNAME_USR_BIN=$(/usr/bin/uname 2>/dev/null)"; \
    echo "OS_SYSTEM_UNAME_ONLY=$(uname 2>/dev/null)"; \
    echo "OS_ARCH_UNAME_BIN=$(/bin/uname -m 2>/dev/null)"; \
    echo "OS_ARCH_UNAME_USR_BIN=$(/usr/bin/uname -m 2>/dev/null)"; \
    echo "OS_ARCH_UNAME_ONLY=$(uname -m 2>/dev/null)"; \
    echo "OS_PWD_USR_BIN=$(/usr/bin/pwd 2>/dev/null)"; \
    echo "OS_PWD_BIN=$(/bin/pwd 2>/dev/null)"; \
    echo "OS_PWD_ONLY=$(pwd 2>/dev/null)"; \
    echo "OS_ENDIAN_BIN=$(/bin/head -c6 /bin/ls 2>/dev/null | \
        /bin/tail -c1 2>/dev/null | \
        /bin/tr "\001\002" "LB" 2>/dev/null)"; \
    echo "OS_ENDIAN_USR_BIN=$(/usr/bin/head -c6 /usr/bin/ls 2>/dev/null | \
        /usr/bin/tail -c1 2>/dev/null | \
        /usr/bin/tr "\001\002" "LB" 2>/dev/null)"; \
    echo "OS_ENDIAN_ONLY=$(head -c6 /usr/bin/env 2>/dev/null | \
        tail -c1 2>/dev/null | \
        tr "\001\002" "LB" 2>/dev/null)"; \
    echo "OS_BITS_BIN=$(/bin/head -c5 /bin/ls 2>/dev/null | \
        /bin/tail -c1 2>/dev/null | \
        /bin/tr "\001\002" "36" 2>/dev/null)"; \
    echo "OS_BITS_USR_BIN=$(/usr/bin/head -c5 /usr/bin/ls 2>/dev/null | \
        /usr/bin/tail -c1 2>/dev/null | \
        /usr/bin/tr "\001\002" "36" 2>/dev/null)"; \
    echo "OS_BITS_ONLY=$(head -c5 /usr/bin/env 2>/dev/null | \
        tail -c1 2>/dev/null | \
        tr "\001\002" "36" 2>/dev/null)"; \
    echo "OS_CAT_PATH=$(if [ -x /usr/bin/cat ]; then echo '/usr/bin/cat'; \
        elif [ -x /bin/cat ]; then echo '/bin/cat'; \
        else echo 'cat'; fi)"; \
    echo "OS_LS_PATH=$(if [ -x /usr/bin/ls ]; then echo '/usr/bin/ls'; \
        elif [ -x /bin/ls ]; then echo '/bin/ls'; else echo 'ls'; fi)"; \
    echo "OS_RM_PATH=$(if [ -x /usr/bin/rm ]; then echo '/usr/bin/rm'; \
        elif [ -x /bin/rm ]; then echo '/bin/rm'; else echo 'rm'; fi)"; \
    echo "OS_SETFATTR_PATH=$(if [ -x /usr/bin/setfattr ]; then echo '/usr/bin/setfattr'; \
        elif [ -x /bin/setfattr ]; then echo '/bin/setfattr'; else echo 'setfattr'; fi)"; \
    echo "OS_SUDO_PATH=$(if [ -x /usr/bin/sudo ]; \
            then echo '/usr/bin/sudo'; \
        elif [ -x /bin/sudo ]; then echo '/bin/sudo'; \
        elif [ -x /usr/local/bin/sudo ]; \
            then echo '/usr/local/bin/sudo'; fi)"; \
    echo "OS_ARM_VFP=$(if grep vfp /proc/cpuinfo >/dev/null 2>/dev/null; then echo 'VFP'; else echo 'NOVFP'; fi)"; \
    echo "OS_END_DATA"
}

function validate () {
    local input="$1"
    local regexes=(
         "^mkdir\s+[\"]$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\"]\s+&&\s+chmod\s+700\s+[\"]$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\"]\s*$"
        "^(|/bin/|/usr/bin/)cat\s+>\s+[\"\']$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)[\"\']\s+&&\s+chmod\s+500\s+[\"\']$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)[\"\']\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+[\"]cd\s+\\\\\"$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\\\\\"\s+&&\s+\\\\\"$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)\\\\\"\s+-z\s+[0-9]+\s+-s\s+[0-9]+\s+-t\s+[0-9]+\s+-n\s+-?[0-9]+\s+-i\s+-h\s+[0-9a-f]{64}(|\s+\-w\s+[0-9]+)[\"]\s*$"
        "^cd\s+[\"]$HOME[\"]\s+&&\s+[\"](|/bin/|/usr/bin/)ls[\"]\s+-1d\s+([ TZ.a-f0-9/]+|\*/)\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+[\"]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)[\"]\s+-x\s+[\"](|$HOME/)[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\"]+\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+(|/bin/|/usr/bin/)id\s*$"
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+[\"]+(|/bin/|/usr/bin/|)rm[\"]\s+-rf\s+[\"]$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}[\"]+\s*$"
        "^LANG=C\s+(|/bin/|/usr/bin/)sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+[\"\\]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)[\"\\]+\s+-k\s+[\"\\]+$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)\.pid[\"\\]+\s*$"
    )
    for rex in "${regexes[@]}"; do
        if [[ $input =~ $rex ]]; then
            return 0
        fi
    done
    return 1
}

cmd=$(printf "%s" "$SSH_ORIGINAL_COMMAND" | sed ':a;N;$!ba;s/\\\n[ \t]*//g')
cmd="${cmd//\| \\$'\n'/| }" 
exec_cmd="${cmd}"

# need to intercept this and take control of the response
if [[ $cmd == "sh" ]]; then
    osprobe
    exit 0
fi

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
