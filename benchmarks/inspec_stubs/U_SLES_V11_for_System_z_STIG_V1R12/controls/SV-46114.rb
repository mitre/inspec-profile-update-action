control 'SV-46114' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'Check if the system is configured for IPv4 forwarding. If the system is a VM host and acts as a router solely for the benefits of its client systems, then this rule is not applicable.

Procedure:
# cat /proc/sys/net/ipv4/ip_forward

If the value is set to "1", IPv4 forwarding is enabled this is a finding.'
  desc 'fix', 'Edit "/etc/sysctl.conf" and set net.ipv4.ip_forward to "0". Restart the system or run "sysctl -p" to make the change take effect.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43371r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12023'
  tag rid: 'SV-46114r1_rule'
  tag stig_id: 'GEN005600'
  tag gtitle: 'GEN005600'
  tag fix_id: 'F-39455r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
