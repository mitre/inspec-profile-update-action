control 'SV-45992' do
  title 'The system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine if the system is configured to forward IPv6 source-routed packets.

Procedure:
# sysctl net.ipv6.conf.all.forwarding
# sysctl net.ipv6.conf.default.forwarding
If any value of the entries is not = "0", this is a finding.'
  desc 'fix', 'Configure the system to not forward IPv6 source-routed packets.

Procedure:
Edit the /etc/sysctl.conf file to include:
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

Reload the kernel parameters:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43274r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22553'
  tag rid: 'SV-45992r1_rule'
  tag stig_id: 'GEN007920'
  tag gtitle: 'GEN007920'
  tag fix_id: 'F-39357r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
