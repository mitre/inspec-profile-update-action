control 'SV-46106' do
  title 'The system must not accept source-routed IPv6 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'The ability to control the acceptance of source-routed packets is not inherent to IPv6.'
  desc 'fix', 'The ability to control the acceptance of source-routed packets is not inherent to IPv6.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43363r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22554'
  tag rid: 'SV-46106r1_rule'
  tag stig_id: 'GEN007940'
  tag gtitle: 'GEN007940'
  tag fix_id: 'F-40351r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
