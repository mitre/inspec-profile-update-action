control 'SV-46276' do
  title 'The system must prevent local applications from generating source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.'
  desc 'check', 'Check the reverse source route settings for the system:
# sysctl net.ipv4.conf.all.accept_source_route
# sysctl net.ipv4.conf.default.accept_source_route

If either setting has a value other than zero, this is a finding.'
  desc 'fix', 'Add the entries in /etc/sysctl.conf to disable reverse source routing:
# printf "sysctl net.ipv4.conf.all.accept_source_route = 0\\n" >> /etc/sysctl.conf
# printf "sysctl net.ipv4.conf.default.accept_source_route = 0\\n" >> /etc/sysctl.conf

Activate the updated settings:
# /sbin/sysctl -p /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43433r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22413'
  tag rid: 'SV-46276r1_rule'
  tag stig_id: 'GEN003606'
  tag gtitle: 'GEN003606'
  tag fix_id: 'F-39576r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
