#!/usr/bin/env bash
##
## a ssh force-command whitelist script for sandflysecurity.com's sandfly(tm)
##
## version 5.1.1.0 // th(at)bogus.net
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
69a58538b99ab89a9f13ae1a5d89ae2eb2970878c899e03c76954284e650239183c2f9feeefa42fa5bcaaf1510a617ba9e06ceae3c6f1da00f27ba75d3178375 *sandfly.386
9babfd742f384873f9da37f91f5a708f52982ff066ea92bd607ae182ce420a8ce0ca39eb381639c5fb6a786513e6eb7ac4db44d09acf8e54ddad18e651cb8acb *sandfly.amd64
763a90e4d7b7d5d217bc06b2ca42f6de02557796d9ab22040a59e9dc4e44db34bc1c9c4de408c48c24163419727e31fa7c4e64b00ba47606b062ebd0d4d2e92d *sandfly.arm
eff96f49b6e8cedd1c03ffcfd5407f0f46e95c2c4cd7fb609cc6bb4cd7107b346b4e7ab96f3f63ba620e8a3f37f7f2bd973b842a644be13d87cd915aad2e34d6 *sandfly.arm5
944bb197483967b12ddfed9fa951f3a3577fcb752ed19da2ba5281d44c5deeb65b70c669017e02199d68cfde225dd1040aa70f87d2f8a59eff5d05767f6961cb *sandfly.arm6
cbe38e675ca43a0a775d89aebbdef856944c0d5933a25dec3c029fa64912740fd688c7cc53b27fa1a5f22fa985a0ba21fb4156de96542980e2421d2d9c572513 *sandfly.arm64
2049944854a5effa77e7bbbfbc6823bf604c31bb0853addc4b9836af7c66c1c5192892be2e864b31df2890174ed0b5ba38cd606dd678579f05c728c15c764ec3 *sandfly.arm7
af022e5423e409b597b63649a24755b9b2d607fc73b8fdfc5fb657a0a23e4eee5b89b824a9bcd335218281dd1ebdfc24fb583c8a2a2cc0520fd4e59a3059aa8c *sandfly.mips
55bfb49044bc36e738e86e267edf994d2a6ed51e4d93a5e48d74cc1c61fddd83bb145348f817f82ea212186f68ddb0552ee1d02d581fe9e717c5a2bd46c93928 *sandfly.mips64
81122bdaf3401dfc80da154716ab19d2aea0a75ae36420eeb7c4ba633b003d3ed1c157aa1fb14e5efd95901d1778cf4935ed07db120e1d0b9a9a11febf3fb543 *sandfly.mips64le
72d582d3da3bbbdcbffa7ed49fc6bf1d5e03fedae05e1d82e5e0c5535c684dc92152d4a2e48af6c35980eca263a5eb6b4be02a6c32a91e61bbcb77b08892f355 *sandfly.mipsle
60d40155b019a34a284b9a112201883c0003e524c46b5d660943b87e0f33280ebf12a9ddf9869d0548c5512841c1dd8b1abb4213219a4f4f3597d8ace6156fce *sandfly.ppc64le
fe55a8d00ab8e14c696e370e4fa7866e6ac6d976ecaf2c7440c06ec87068cedb2f7f80ab3d83cd7932e728dbb37e9d004813410c60b7e0a6782ec2e4b1d2370e *sandfly.s390x
EOF
)

cmd="${SSH_ORIGINAL_COMMAND//$'\t'/}"
cmd="${cmd//\| \\$'\n'/| }"
cmd="${cmd//sh \\$'\n'/sh }"
exec_cmd="${cmd// \\ echo/echo}"
cmd="${cmd//; \\/}"
cmd="${cmd//null \\ |/null |}" # ignore stray "\ |" when checking OS_ENDIAN_USR_BIN (introduced in 5.1.1)

function validate () {
    input=$1
    rex_1="^echo \"[A-Z_]+\"\s*$"
    rex_2="^echo \"[A-Z_]+=\\$\((|/bin/|/usr/bin/)(pwd|id|uname)\s+(|(-u|-m)\s+)2>/dev/null\)\"\s*$"
    rex_3="^echo \"[A-Z_]+=\\$\(which\s+(cat|ls|rm)\s+2>/dev/null\)\"\s*$"
    rex_4="^echo \"[A-Z_]+=\\$\((|/bin/|/usr/bin/)head\s+-c\s*6\s+(|/bin/|/usr/bin/)ls\s+2>/dev/null\s*\|\s*(|/bin/|/usr/bin/)tail\s+-c\s*1\s+2>/dev/null\s*\|\s*(|/bin/|/usr/bin/)tr\s+\"\\\001\\\002\"\s+\"LB\"\s+2>/dev/null\)\"\s*$"
    rex_5="^echo \"[A-Z_]+=\\$\(head\s+-c\s*6\s+\\$\(which\s+ls\s+2>/dev/null\)\s+2>/dev/null\s+\|\s+tail\s+-c\s*1\s+2>/dev/null\s+\|\s+\tr\s+\"\\\001\\\002\"\s+\"LB\"\s+2>/dev/null)\"\s*$"
    rex_6="^mkdir\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s+&&\s+chmod\s+700\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.\s*$"
    rex_7="^(|/bin/|/usr/bin/)cat\s+>\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+&&\s+chmod\s+500\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s*$"
    rex_8="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+.cd\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s+&&\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+.[-\ a-z0-9]+.\s*$"
    rex_9="^cd\s+.$HOME.\s+&&\s+.(|/bin/|/usr/bin/)ls.\s+-1d\s+([ TZ.a-f0-9/]+|\*/)\s*$"
    rex_10="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames).\s+-x\s+.(|$HOME/)[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}..\s*$"
    rex_11="^LANG=C\s+sudo\s+-S\s+(|/bin/|/usr/bin/)id\s*$"
    rex_12="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+..(|/bin/|/usr/bin/|)rm.\s+-rf\s+.$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}.."
    rex_13="^LANG=C\s+sudo\s+-S\s+LANG=C\s+/bin/sh\s+-c\s+...$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)..\s+-k\s+..$HOME/[0-9]{8}T[0-9]{6}Z\.[a-f0-9]{16}/($agentbinarynames)\.pid...\s*$"
    if [[ $input =~ $rex_1 || $input =~ $rex_2 || $input =~ $rex_3 || $input =~ $rex_4 ||$input =~ $rex_5 ||
          $input =~ $rex_6 || $input =~ $rex_7 || $input =~ $rex_8 || $input =~ $rex_9 || $input =~ $rex_10 ||
          $input =~ $rex_11 || $input =~ $rex_12 || $input =~ $rex_13 ]]
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