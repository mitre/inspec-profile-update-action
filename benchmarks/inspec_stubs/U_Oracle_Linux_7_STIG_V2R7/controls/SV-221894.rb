control 'SV-221894' do
  title 'The Oracle Linux operating system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'If IPv6 is not enabled, the key will not exist, and this is Not Applicable.

Verify the system does not accept IPv6 source-routed packets.

# grep net.ipv6.conf.all.accept_source_route /etc/sysctl.conf /etc/sysctl.d/*

net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "0", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

# /sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route = 0

If the returned lines do not have a value of "0", this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter, if IPv6 is enabled, by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

net.ipv6.conf.all.accept_source_route = 0

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23609r419754_chk'
  tag severity: 'medium'
  tag gid: 'V-221894'
  tag rid: 'SV-221894r603260_rule'
  tag stig_id: 'OL07-00-040830'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23598r419755_fix'
  tag 'documentable'
  tag legacy: ['SV-108631', 'V-99527']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
