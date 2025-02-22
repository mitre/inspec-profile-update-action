control 'SV-219057' do
  title 'AIX must employ a deny-all, allow-by-exception firewall policy for allowing connections to other systems.'
  desc 'Failure to restrict network connectivity only to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate exfiltration of DoD data.'
  desc 'check', 'From the command prompt, run the following commands to check if the "all traffic" filter rules, the predefined rule with Rule-ID 0, are defined to deny all packages:

# lsfilt -v4 -n0
# lsfilt -v6 -n0 

Rule 0:
Rule action         : deny
Source Address      : 0.0.0.0
Source Mask         : 0.0.0.0
Destination Address : 0.0.0.0
Destination Mask    : 0.0.0.0
Source Routing      : yes
Protocol            : all
Source Port         : any 0
Destination Port    : any 0
Scope               : both
Direction           : both
Logging control     : no
Fragment control    : all packets
Tunnel ID number    : 0
Interface           : all
Auto-Generated      : no
Expiration Time     : 0
Description         : Default Rule

Rule 0:
Rule action         : deny
Source Address      : ::
Source Mask         : 0
Destination Address : ::
Destination Mask    : 0
Source Routing      : yes
Protocol            : all
Source Port         : any 0
Destination Port    : any 0
Scope               : both
Direction           : both
Logging control     : no
Fragment control    : all packets
Tunnel ID number    : 0
Interface           : all
Auto-Generated      : no
Expiration Time     : 0
Description         : Default Rule

If any of the "all traffic" rules has "Rule action : permit", this is a finding.'
  desc 'fix', 'From the command prompt, run the following commands to create and activate "ipsec_v4" and "ipsec_v6" devices:
# mkdev -l ipsec -t 4
# mkdev -l ipsec -t 6

From the command prompt, run the following commands to change the "all traffic" rules to block all packages:
# chfilt -a D -v 4 -n 0
# chfilt -a D -v 6 -n 0

Assume that the local host has IP address 10.10.10.10 and the remote host has IP address 11.11.11.11, run the following command to generate a user-defined filter rule that allow all IPv4 traffic between these 2 hosts:
# genfilt -w B -v 4 -s 10.10.10.10 -p 0 -P 0 -o any -O any -m 255.255.255.255 -M 255.255.255.255 -i all -g Y -d 11.11.11.11 -c all -a P

From the command prompt, run the following command to activate all the filter rules in the rule database:
# mkfilt -u'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-20868r294777_chk'
  tag severity: 'medium'
  tag gid: 'V-219057'
  tag rid: 'SV-219057r853494_rule'
  tag stig_id: 'AIX7-00-003143'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20867r294778_fix'
  tag 'documentable'
  tag legacy: ['V-91771', 'SV-101869']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
