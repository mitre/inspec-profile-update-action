control 'SV-38828' do
  title 'The system must not accept source-routed IPv6 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'fix', 'Configure the system to not accept source-routed IPv6 packets. 
# /usr/sbin/no -p -o ipsrcrouterecv=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22554'
  tag rid: 'SV-38828r1_rule'
  tag stig_id: 'GEN007940'
  tag gtitle: 'GEN007940'
  tag fix_id: 'F-32352r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
