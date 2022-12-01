# very short intro
Sandfly is a Linux security product (see https://sandflysecurity.com).

# sandfly-restrict
An ssh force-command script that adds additional controls to the "sandfly" user's execution environment. In addition to 
whitelisting of commands using regular expressions, the script will also verify the sha256sum of the "sandfly" binary.

# usage
Put restrict.sh in an appropriate directory (_/usr/local/bin_) with appropriate permissions (e.g. _chmod 755_). 
Prepend the "sandfly" user's _.ssh/authorized_keys_ file with _command="/usr/local/bin/restrict.sh",no-agent-forwarding,
no-port-forwarding,no-user-rc,no-X11-forwarding_, like so:
```
mcfly@test:~$ cat .ssh/authorized_keys
command="/usr/local/bin/restrict.sh",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA.....eO mcfly@test
```
# read the fine script
Recent versions of Sandfly support the use of random binary names to reduce detection. If you use this feature, this script requires 
some tweaking of the regular expression matching (look for "botfly" within the script and take it from there). 

# end note
I have no affiliation with Sandfly, Inc.; I merely find the product interesting.
