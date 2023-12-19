control 'SV-45724' do
  title 'The system must not accept source-routed IPv4 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another system, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Verify the system does not accept source-routed IPv4 packets.

Procedure:
# grep [01] /proc/sys/net/ipv4/conf/*/accept_source_route|egrep "default|all"

If all of the resulting lines do not end with "0", this is a finding.'
  desc 'fix', 'Configure the system to not accept source-routed IPv4 packets.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.accept_source_route=0" and "net.ipv4.conf.default.accept_source_route=0". 

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43091r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22414'
  tag rid: 'SV-45724r1_rule'
  tag stig_id: 'GEN003607'
  tag gtitle: 'GEN003607'
  tag fix_id: 'F-39122r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
