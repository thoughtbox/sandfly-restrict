# very short intro
Sandfly is a Linux security product (see https://sandflysecurity.com); this script attempts to reduce admin paranoia (at the expense of increasing regex phobia).

# sandfly-restrict
This is an ssh force-command script that adds additional security controls to the "sandfly" user's execution environment. In addition to whitelisting of commands using regular expressions, the script will also verify the sha512sum of the "sandfly" binary.

# usage
Put _restrict.sh_ in an appropriate directory (_/usr/local/bin_) with appropriate permissions (e.g. _chmod 755_). 
Prepend the "sandfly" user's _.ssh/authorized_keys_ file with _command="/usr/local/bin/restrict.sh",no-agent-forwarding,
no-port-forwarding,no-user-rc,no-X11-forwarding_, like so:
```
mcfly@test:~$ cat .ssh/authorized_keys
command="/usr/local/bin/restrict.sh",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA.....eO mcfly@test
```
Additional admin paranoia can be reduced through host-based means such as TCP wrappers, iptables and/or by limiting which hosts that can log in to the "sandfly" user account. The latter can be achieved by prepending a _from=_ option to the above _authorized_keys_ entry. For example, if your Sandfly nodes are on 172.16.16.0/29, your _authorized_keys_ file should look like (note, NO SPACES unless they are within double quotes):
```
mcfly@test:~$ cat .ssh/authorized_keys
from="172.16.16.0/29",command="/usr/local/bin/restrict.sh",no-agent-forwarding,no-port-forwarding,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA.....eO mcfly@test
```

# read the fine script
Sandfly supports the use of random binary names to reduce detection. If you use this feature, this script requires some tweaking of the regular expression matching (look for "botfly" within the script and take it from there). 

# compatibility
This version has been tested to work with Sandfly version 5.2.0; AKA "it works for me". 

# end note
I have no affiliation with Sandfly Security, Ltd.; I merely find the product interesting.
