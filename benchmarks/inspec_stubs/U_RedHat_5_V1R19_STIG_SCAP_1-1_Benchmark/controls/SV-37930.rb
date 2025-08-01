control 'SV-37930' do
  title 'The system must not have IP forwarding for IPv6 enabled, unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'fix', 'Disable IPv6 forwarding.

Edit /etc/sysctl.conf and add a setting for "net.ipv6.conf.all.forwarding=0" and "net.ipv6.conf.default.forwarding=0".

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22491'
  tag rid: 'SV-37930r2_rule'
  tag stig_id: 'GEN005610'
  tag gtitle: 'GEN005610'
  tag fix_id: 'F-32423r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
