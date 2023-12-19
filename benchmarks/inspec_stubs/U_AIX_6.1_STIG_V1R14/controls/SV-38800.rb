control 'SV-38800' do
  title 'The system must not accept source-routed IPv4 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another, such as when IPv4 forwarding is enabled and the system is functioning as a router'
  desc 'check', '# /usr/sbin/no -o ipsrcrouterecv 
If the result is not 0,  this is a finding.'
  desc 'fix', 'Configure the system to not accept source-routed IPv4 packets.  
#/usr/sbin/no -p -o ipsrcrouterecv=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37256r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22414'
  tag rid: 'SV-38800r1_rule'
  tag stig_id: 'GEN003607'
  tag gtitle: 'GEN003607'
  tag fix_id: 'F-32497r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
