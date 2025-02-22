control 'SV-26228' do
  title 'The system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine if the system is configured to forward IPv6 source-routed packets. If it is, this is a finding.'
  desc 'fix', 'Configure the system to not forward IPv6 source-routed packets.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22553'
  tag rid: 'SV-26228r1_rule'
  tag stig_id: 'GEN007920'
  tag gtitle: 'GEN007920'
  tag fix_id: 'F-26343r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
