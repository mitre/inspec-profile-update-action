control 'SV-26076' do
  title 'The system must prevent local applications from generating source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Determine if the system is configured to prevent local applications from generating source-routed packets.  If this is not prevented, this is a finding.'
  desc 'fix', 'Configure the system to prevent local applications from generating source-routed packets.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22413'
  tag rid: 'SV-26076r1_rule'
  tag stig_id: 'GEN003606'
  tag gtitle: 'GEN003606'
  tag fix_id: 'F-26270r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
