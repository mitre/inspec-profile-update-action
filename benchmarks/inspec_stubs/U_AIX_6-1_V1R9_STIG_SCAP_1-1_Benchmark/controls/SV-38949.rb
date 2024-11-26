control 'SV-38949' do
  title 'The system must prevent local applications from generating source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'fix', '# /usr/sbin/no -po "ipsrcroutesend=0"'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22413'
  tag rid: 'SV-38949r1_rule'
  tag stig_id: 'GEN003606'
  tag gtitle: 'GEN003606'
  tag fix_id: 'F-32496r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
