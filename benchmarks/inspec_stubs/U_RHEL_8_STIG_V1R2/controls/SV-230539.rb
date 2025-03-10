control 'SV-230539' do
  title 'RHEL 8 must not forward source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify RHEL 8 does not accept source-routed packets by default.

Note: If either IPv4 or IPv6 is disabled on the system, this requirement only applies to the active internet protocol version.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_source_route net.ipv6.conf.default.accept_source_route

net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

If the returned lines do not have a value of "0", a line is not returned, or either returned line is commented out, this is a finding.'
  desc 'fix', %q(Configure RHEL 8 to not forward source-routed packets by default with the following commands:

$ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

$ sudo sysctl -w net.ipv6.conf.default.accept_source_route=0

If "0" is not the system's default value then add or update the following lines in the appropriate file under "/etc/sysctl.d":

net.ipv4.conf.default.accept_source_route=0

net.ipv6.conf.default.accept_source_route=0)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33208r568363_chk'
  tag severity: 'medium'
  tag gid: 'V-230539'
  tag rid: 'SV-230539r627750_rule'
  tag stig_id: 'RHEL-08-040250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33183r568364_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
