control 'SV-29707' do
  title 'The system must prevent local applications from generating source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'fix', 'Edit /etc/opt/ipf/ipf.conf and add rules to block outgoing 
source-routed packets, such as:
block out log quick all with opt lsrr
block out log quick all with opt ssrr

Reload the IPF rules.
# ipf -Fa -A -f /etc/opt/ipf/ipf.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22413'
  tag rid: 'SV-29707r1_rule'
  tag stig_id: 'GEN003606'
  tag gtitle: 'GEN003606'
  tag fix_id: 'F-31866r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
