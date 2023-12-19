control 'SV-215429' do
  title 'AIX must not process ICMP timestamp requests.'
  desc 'The processing of Internet Control Message Protocol (ICMP) timestamp requests increases the attack surface of the system.'
  desc 'check', 'From the command prompt, run the following command to check if "ipsec_v4" and "ipsec_v6" devices are active:
# lsdev -Cc ipsec

The above command should yield the following output:
ipsec_v4 Available  IP Version 4 Security Extension
ipsec_v6 Available  IP Version 6 Security Extension

If "ipsec_v4" or "ipsec_v6" is not displayed, or it is not in "Available" state, this is a finding.

Determine if the system is configured to respond to ICMP Timestamp requests using the following command: 
# lsfilt

Beginning of IPv4 filter rules.
Rule 1:
Rule action         : permit
Source Address      : 0.0.0.0
Source Mask         : 0.0.0.0
Destination Address : 0.0.0.0
Destination Mask    : 0.0.0.0
Source Routing      : no
Protocol            : udp
Source Port         : eq  4001
Destination Port    : eq  4001
Scope               : both
Direction           : both
Logging control     : no
Fragment control    : all packets
Tunnel ID number    : 0
Interface           : all
Auto-Generated      : yes
Expiration Time     : 0
Description         : Default Rule

Rule 2:
*** Dynamic filter placement rule for IKE tunnels ***
Logging control     : no

Rule 3:
Rule action         : deny
Source Address      : 0.0.0.0
Source Mask         : 0.0.0.0
Destination Address : 0.0.0.0
Destination Mask    : 0.0.0.0
Source Routing      : yes
Protocol            : icmp
ICMP type           : any 0
ICMP code           : eq  13
Scope               : both
Direction           : inbound
Logging control     : no
Fragment control    : all packets
Tunnel ID number    : 0
Interface           : all
Auto-Generated      : no
Expiration Time     : 0
Description         : 

Rule 4:
Rule action         : deny
Source Address      : 0.0.0.0
Source Mask         : 0.0.0.0
Destination Address : 0.0.0.0
Destination Mask    : 0.0.0.0
Source Routing      : yes
Protocol            : icmp
ICMP type           : eq  14
ICMP code           : any 0
Scope               : both
Direction           : outbound
Logging control     : no
Fragment control    : all packets
Tunnel ID number    : 0
Interface           : all
Auto-Generated      : no
Expiration Time     : 0
Description         : 

Rule 0:
Rule action         : permit
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

End of IPv4 filter rules.

If there is no rule blocking ICMP packet type of "13" and ICMP packet type of "14" (rule #3 and rule #4 above), this is a finding.'
  desc 'fix', 'From the command prompt, run the following commands to create and activate "ipsec_v4" and "ipsec_v6" devices:
# mkdev -l ipsec -t 4
# mkdev -l ipsec -t 6

Run the following commands to create 2 IPsec rules to block the ICMP timestamp request and reply:
# genfilt -v 4 -a D -s 0 -m 0 -d 0 -M 0 -c icmp -O eq -P 13 -r B -w I -i all
# genfilt -v 4 -a D -s 0 -m 0 -d 0 -M 0 -c icmp -o eq -p 14 -r B -w O -i all

From the command prompt, run the following command to activate all the filter rules in the rule database:
# mkfilt -u'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16627r294738_chk'
  tag severity: 'medium'
  tag gid: 'V-215429'
  tag rid: 'SV-215429r508663_rule'
  tag stig_id: 'AIX7-00-003134'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16625r294739_fix'
  tag 'documentable'
  tag legacy: ['V-91719', 'SV-101817']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
