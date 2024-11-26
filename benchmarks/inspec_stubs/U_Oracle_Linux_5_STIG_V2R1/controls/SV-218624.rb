control 'SV-218624' do
  title 'The system must not have IP forwarding for IPv6 enabled, unless the system is an IPv6 router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', 'Check if the system is configured for IPv6 forwarding.

# grep [01] /proc/sys/net/ipv6/conf/*/forwarding|egrep "default|all"

If the /proc/sys/net/ipv6/conf/*/forwarding entries do not exist because of compliance with GEN007720, this is not a finding.

If all of the resulting lines do not end with 0, this is a finding.'
  desc 'fix', 'Disable IPv6 forwarding.

Edit /etc/sysctl.conf and add a setting for "net.ipv6.conf.all.forwarding=0" and "net.ipv6.conf.default.forwarding=0".

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20099r556070_chk'
  tag severity: 'medium'
  tag gid: 'V-218624'
  tag rid: 'SV-218624r603259_rule'
  tag stig_id: 'GEN005610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20097r556071_fix'
  tag 'documentable'
  tag legacy: ['V-22491', 'SV-64245']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
