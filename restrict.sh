#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.6 // th(at)bogus.net
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
acc36a85251b584ee0543e8b195a44afbc9c596cf0b2d1bfe1010dfc6436a9480e5cbb2aa3edc58b5359cdb4cab7a55c2e529a1754c57d9f3457d5f2346a3d28  sandfly.386
3527ee6403f0c46c403470d1e88d6c0dd9b728909e8d20fe4ac8283ae98637e471db1c346142a39862785885ea3e7f430e554c657ecf96c8de3709f11dd9f76b  sandfly.amd64
e93546cf2f68e3172a5abe2a8dc9ea0475328192529dc77e0e2b6d1649694aeecae61ae779de7d8d50c7e5c6b142ccb0e0dd64a29d178f258e6b902c2716ab90  sandfly.arm
374ca20d202b7ff22ede308b2eb4c98ee6691a38b48966dd749f9f8df23d33c00d544f35cc2b41345c1574e4c973c782ca585e49168c0d036657758e2a90526e  sandfly.arm5
6c9bbfd7861f523eb0f43787da6aa79dacf6658bfb2c62e62ded6917250b747466b975ab941d7602f00641256783b8ce90b11da40ae1679dcd09e0a4cfd8cd56  sandfly.arm6
714ee92f891495f205543601ec14c6531690d5fbbd9e77e89202822474408c4fff6789232b23feeaead5e5f3a89a8f857db278af54ea4587b3ef4d7ca8efad36  sandfly.arm64
e95ed1a6212b097a638b1a28028c8e9d74be1511ae95bd958cfeabd195278a76b6ce55e353a1a6f02c9f406803f8f37357c24cc19f3ea4a62f2f7956cd31f8a5  sandfly.arm7
a91cfe66a13ae2bb08bf968833f48f65c1f1fcef5a5e6dc3c788a655c3045626c27bd8b40e99114aaa5577d446f0962edeb2d6a9ff7938ab5071c5af8f225438  sandfly.mips
0b68d25ce86417b2a88e65b8fcdf21b06d076d6db438232bcd35ea2f6cb7f658dd655b03561f01d2c61984d17a2d12b0abec78cbd54c20e1433cf7162393ded2  sandfly.mips64
737714bc3b6c245e81011b2b565e0b82406f1b779edd3c2817c8447cfff03713473e085436d706afd11be871af0c630e36a268de2590948c69b1fa5c61c7144a  sandfly.mips64le
c325486719ecebc3eec254ac49139db42111de16abcaaded323fe0872b4a34287f96fcb3ade64ec7854fcf96968c2cc1b8558983e5fe435a5e5a5a34203a1dc5  sandfly.mipsle
ead1b1049946464d27fae815d35ff591c361582b981036fe5d2b61ece29f0a07b9d575067e874a6efe50ff533e1f3b6fa064d90cde36a9b3f125c8c719cd09b2  sandfly.ppc64le
f4730c14986584021a929048edf3862c561464ba2e9efb95db7e42a7b4e0e6be0acbead82436e65ede5469111996e0d00bd9543e02de25e1b4d65a2c4d37059d  sandfly.s390x
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
