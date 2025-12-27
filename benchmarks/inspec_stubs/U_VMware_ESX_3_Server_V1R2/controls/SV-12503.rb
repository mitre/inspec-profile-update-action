control 'SV-12503' do
  title 'The system must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'If the system is configured to forward source-routed packets, this is a finding.'
  desc 'fix', 'Configure the system to not forward source-routed packets.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7966r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12002'
  tag rid: 'SV-12503r2_rule'
  tag stig_id: 'GEN003600'
  tag gtitle: 'GEN003600'
  tag fix_id: 'F-11262r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
