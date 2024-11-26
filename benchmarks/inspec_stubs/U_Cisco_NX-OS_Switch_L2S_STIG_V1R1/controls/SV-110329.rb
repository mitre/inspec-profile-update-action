control 'SV-110329' do
  title 'The Cisco switch must be configured for authorized users to select a user session to capture.'
  desc 'Without the capability to select a user session to capture/record or view/hear, investigations into suspicious or harmful events would be hampered by the volume of information captured. The volume of information captured may also adversely impact the operation for the network. Session audits may include port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Verify that the switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session. The example configuration below will capture packets from interface Ethernet1/66 and replicate the packets to interface Ethernet1/68.

monitor session 1 
 source interface Ethernet1/66 both
 destination interface Ethernet1/68

If the switch is not capable of capturing ingress and egress packets from a designated switch port, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session. The example configuration below will capture packets from interface Ethernet1/66 and replicate the packets to Ethernet1/68.

SW1(config)# monitor session 1
SW1(config-monitor)# source interface ethernet 1/66
SW1(config-monitor)# destination interface ethernet 1/68
SW1(config-monitor)# end'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101225'
  tag rid: 'SV-110329r1_rule'
  tag stig_id: 'CISC-L2-000060'
  tag gtitle: 'SRG-NET-000331-L2S-000001'
  tag fix_id: 'F-106929r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
