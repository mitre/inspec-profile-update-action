control 'SV-29713' do
  title 'The system must not accept source-routed IPv4 packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the handling of source-routed traffic destined to the system itself, not to traffic forwarded by the system to another, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'fix', 'Edit /etc/opt/ipf/ipf.conf and add rules to block incoming 
source-routed packets, such as:

block in log quick all with opt lsrr
block in log quick all with opt ssrr

Reload the IPF rules.
# ipf -Fa -A -f /etc/opt/ipf/ipf.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22414'
  tag rid: 'SV-29713r1_rule'
  tag stig_id: 'GEN003607'
  tag gtitle: 'GEN003607'
  tag fix_id: 'F-31869r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
