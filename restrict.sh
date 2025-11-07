#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.5.4.0 // th(at)bogus.net
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
77949be507bf1ada04ab6a81b6ce72c6809e17e5787b797aeb4f4c2baab0d2c84a48013e462c9826cd3536c9c7258b2081f9e535c0ab547196b682cccd5c12ee *sandfly.386
41568d72d7a28d2a58b7ec189aee5b67290e69bc6d917d516608e44452dec7e6a3fa9b3930c7830d76de8118def4150f93861fd5a648508015de68dc9df88c0d *sandfly.agents.sha256.txt
a9920053928d3d00533fe93aae18b5caec27dc7d76f250cbd172fda573146a8f873c570d150dc3c3a2f1bd77763b19f187212bd01764392d76276f852fae72ef *sandfly.amd64
0187edbfa5b15dc320f193a782752661a27c8ecfbafb7a6ff303903aab283469bc9e917b20191844386aa865eecbfa72a9a32941974516bbdaa61a0aa6b73173 *sandfly.arm
c30f1c24603a9db673b2b22576455212a7556210c70e0cd9ff31a234089d52a2c7bbd7d5dc19cbe7501541c614c0594938e6813f7279faf2f8b29bb9fb97153f *sandfly.arm5
a0e1467465f653c79926824da183756552dcaa7710e89240bc874b72f3aefc80e32845d561be5c9c3fae51f584c91627b20031127008d85833db71dc86fd5a9d *sandfly.arm6
4de50b51466ce3af3a8cbf334795cf8b547c5a6f171538c05bffffe0000c35a0e3fa73e641010497c2da77be85a6559d8dac49b77b8c0ab80587efe1da25cfff *sandfly.arm64
da68c3fa0121c0fe4db8aee421bf0ee43789a4f744b0c57d41fad4cd0131a636b6494b82b9981e7a3edfa58b3574ad6dfbeab9377192568d8ac846ee04e2d43a *sandfly.arm7
a64fc7a5524cf41a894a4d2f3d3902d2d84e4c07ad31f04cb6da8a4a63afe5466d998d64f1893439617d13b8d5af628806c85f09a1d9a336917603a338082406 *sandfly.mips
4b3182baf685753bd48378ae1c1a0226ba3de201f29f09f9507f103dab86937e2f721564542610a4c13574fe4ec2efb907300bfb498746aa015961483dc41ebf *sandfly.mips64
9771147d514d173ea1b32ea293cbabf87118467bd388a1095e2f524b8760d4f6cdd5519e0b9d3dd2bcd03295147c629ce5ec6f0fc3f8028a072c244e42037c61 *sandfly.mips64le
76c3410aed44c02ccbce74d52a21af267b8a4dd11233f3f31f385375f569463081c482764b7344c223c8a113961f6c680dac8edfde5c34ebc7cf83e16496a443 *sandfly.mipsle
83d3cbd903515e02973be4a949e043c91d21108c446582e086bc4ea6dcfddd71f20561f8cfaf14b816d2a30704644014479b9d5303f3d1f0be719304b0db5fc3 *sandfly.ppc64le
f62b77079ea8a5f3568958a28734e309bf7b0b9740f2d7b508919ba04f1540d066925fc6e22977d930190ba09c5961e6e309aadad1a9f7e01fdf619cfc844ee5 *sandfly.s390x
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
        "^LANG=C\s+[\"](|/bin/|/usr/bin/)sudo[\"]\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+[\"]cd\s+\\\\\"$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}\\\\\"\s+&&\s+\\\\\"$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)\\\\\"\s+-z\s+[0-9]+\s+-s\s+[0-9]+\s+-t\s+[0-9]+\s+-n\s+-?[0-9]+\s+-i\s+-h\s+[0-9a-f]{64}[\"]\s*$"
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
