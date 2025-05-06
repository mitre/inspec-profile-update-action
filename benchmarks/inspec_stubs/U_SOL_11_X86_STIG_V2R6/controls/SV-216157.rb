control 'SV-216157' do
  title 'The system must prevent local applications from generating source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Determine the OS version you are currently securing.
# uname –v

Solaris 11, 11.1, 11.2, and 11.3 use IP Filter.  To continue checking IP Filter, the IP Filter Management profile is required.

Check the system for an IPF rule blocking outgoing source-routed packets.

# ipfstat -o

Examine the list for rules such as: 
block out log quick from any to any with opt lsrr
block out log quick from any to any with opt ssrr

If the listed rules do not block both lsrr and ssrr options, this is a finding.

For Solaris 11.3 or newer that use Packet Filter, the Network Firewall Management rights profile is required.

Ensure that IP Options are not in use:
# pfctl -s rules | grep allow-opts

If any output is returned, this is a finding.'
  desc 'fix', 'The root role is required.

# pfedit /etc/ipf/ipf.conf 

For Solaris 11, 11.1, 11.2, and 11.3 that use IP Filter dd rules to block outgoing source-routed packets, such as:

block out log quick all with opt lsrr 
block out log quick all with opt ssrr

Reload the IPF rules.

# ipf -Fa -A -f /etc/ipf/ipf.conf   

For Solaris 11.3 or newer that use Packet Filter remove or modify any rules that include "allow-opts".

Reload the Packet Filter rules:
# svcadm refresh firewall:default'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17395r372853_chk'
  tag severity: 'low'
  tag gid: 'V-216157'
  tag rid: 'SV-216157r603268_rule'
  tag stig_id: 'SOL-11.1-050370'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17393r372854_fix'
  tag 'documentable'
  tag legacy: ['V-48213', 'SV-61085']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
