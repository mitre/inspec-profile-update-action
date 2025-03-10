control 'SV-227799' do
  title 'The system must prevent local applications from generating source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Check the system for an IPF rule blocking outgoing source-routed packets.

Procedure:
# ipfstat -o 

Examine the list for rules such as:
block out log quick all with opt lsrr
block out log quick all with opt ssrr

If the listed rules do not block both lsrr and ssrr options, this is a finding.'
  desc 'fix', 'Edit /etc/ipf/ipf.conf and add rules to block outgoing source-routed packets, such as: 

block out log quick all with opt lsrr
block out log quick all with opt ssrr

Reload the IPF rules.
Procedure:

# ipf -Fa -A -f /etc/ipf/ipf.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29961r489751_chk'
  tag severity: 'medium'
  tag gid: 'V-227799'
  tag rid: 'SV-227799r603266_rule'
  tag stig_id: 'GEN003606'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29949r489752_fix'
  tag 'documentable'
  tag legacy: ['V-22413', 'SV-29709']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
