control 'SV-204630' do
  title 'The Red Hat Enterprise Linux operating system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'If IPv6 is not enabled, the key will not exist, and this is Not Applicable.

Verify the system does not accept IPv6 source-routed packets.

     # grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/* /etc/sysctl.d/* /usr/local/lib/sysctl.d/* /usr/lib/sysctl.d/* /lib/sysctl.d/* /etc/sysctl.conf 2> /dev/null
     net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not configured in the /etc/sysctl.conf file or in any of the other sysctl.d directories, is commented out or does not have a value of "0", this is a finding.

Check that the operating system implements the accept source route variable with the following command:

     # /sbin/sysctl -a | grep net.ipv6.conf.all.accept_source_route
     net.ipv6.conf.all.accept_source_route = 0

If the returned lines do not have a value of "0", this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Set the system to the required kernel parameter, if IPv6 is enabled, by adding the following line to "/etc/sysctl.conf" or a configuration file in the /etc/sysctl.d/ directory (or modify the line to have the required value):

     net.ipv6.conf.all.accept_source_route = 0

Issue the following command to make the changes take effect:

     # sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4754r880825_chk'
  tag severity: 'medium'
  tag gid: 'V-204630'
  tag rid: 'SV-204630r880827_rule'
  tag stig_id: 'RHEL-07-040830'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4754r880826_fix'
  tag 'documentable'
  tag legacy: ['V-72319', 'SV-86943']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
