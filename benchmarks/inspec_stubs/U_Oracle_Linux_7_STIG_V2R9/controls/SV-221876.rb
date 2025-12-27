control 'SV-221876' do
  title 'The Oracle Linux operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the system does not accept IPv4 source-routed packets by default.

# grep net.ipv4.conf.default.accept_source_route /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.conf.default.accept_source_route = 0

If "net.ipv4.conf.default.accept_source_route" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out, or does not have a value of "0", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

# /sbin/sysctl -a | grep net.ipv4.conf.default.accept_source_route
net.ipv4.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

net.ipv4.conf.default.accept_source_route = 0 

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23591r419700_chk'
  tag severity: 'medium'
  tag gid: 'V-221876'
  tag rid: 'SV-221876r603260_rule'
  tag stig_id: 'OL07-00-040620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23580r419701_fix'
  tag 'documentable'
  tag legacy: ['SV-108595', 'V-99491']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
