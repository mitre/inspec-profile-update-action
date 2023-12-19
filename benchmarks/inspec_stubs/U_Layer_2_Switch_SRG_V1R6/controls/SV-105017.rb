control 'SV-105017' do
  title 'The layer 2 switch must have Storm Control configured on all host-facing switch ports.'
  desc 'A traffic storm occurs when packets flood a LAN, creating excessive traffic and degrading network performance. Traffic storm control prevents network disruption by suppressing ingress traffic when the number of packets reaches a configured threshold levels. Traffic storm control monitors ingress traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the switch configuration to verify that storm control is enabled on host-facing interfaces.
 
If storm control is not enabled on all host-facing switch ports, this is a finding.'
  desc 'fix', 'Configure storm control on each host-facing switch ports.'
  impact 0.3
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-94709r1_chk'
  tag severity: 'low'
  tag gid: 'V-95879'
  tag rid: 'SV-105017r1_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000001'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-101547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
