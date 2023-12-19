control 'SV-38378' do
  title 'The system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine if the system is configured for packet forwarding.
# ndd -get /dev/ip6 ip6_forwarding

If the command returns 0 (disabled), this is not a finding. 

If the command returns 1 (enabled), ask the SA if the system is configured to act as a router, this is a finding.'
  desc 'fix', 'Configure the system to not forward IPv6 source-routed packets.   
# ndd -set /dev/ip6 ip6_forwarding 0

This command should also be added to the ndd configuration file and/or to the system startup script /etc/rc.config.d/nddconf :

TRANSPORT_NAME[index]=ip6
NDD_NAME[index]=ip6_forwarding 
NDD_VALUE[index]=0'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36755r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22553'
  tag rid: 'SV-38378r1_rule'
  tag stig_id: 'GEN007920'
  tag gtitle: 'GEN007920'
  tag fix_id: 'F-32139r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
