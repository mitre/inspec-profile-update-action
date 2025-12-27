control 'SV-217289' do
  title 'The SUSE operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the SUSE operating system does not accept IPv4 source-routed packets by default.

Check the value of the default accept source route variable with the following command:

# sysctl net.ipv4.conf.default.accept_source_route
net.ipv4.conf.default.accept_source_route = 0

If the returned line does not have a value of "0" this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):

net.ipv4.conf.default.accept_source_route = 0

Run the following command to apply this value:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18517r370023_chk'
  tag severity: 'medium'
  tag gid: 'V-217289'
  tag rid: 'SV-217289r603262_rule'
  tag stig_id: 'SLES-12-030370'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18515r370024_fix'
  tag 'documentable'
  tag legacy: ['V-77489', 'SV-92185']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
