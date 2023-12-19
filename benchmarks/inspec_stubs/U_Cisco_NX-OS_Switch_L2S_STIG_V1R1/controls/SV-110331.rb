control 'SV-110331' do
  title 'The Cisco switch must be configured for authorized users to remotely view, in real time, all content related to an established user session from a component separate from The Cisco switch.'
  desc 'Without the capability to remotely view/hear all content related to a user session, investigations into suspicious user activity would be hampered. Real-time monitoring allows authorized personnel to take action before additional damage is done. The ability to observe user sessions as they are happening allows for interceding in ongoing events that after-the-fact review of captured content would not allow.'
  desc 'check', 'Verify that the switch is capable of capturing ingress and egress packets from any designated switch port for the purpose of remotely monitoring a specific user session. The example configuration below will capture packets from interface Ethernet1/66 and replicate the packets to interface Ethernet1/68.

monitor session 1 
 source interface Ethernet1/66 both
 destination interface Ethernet1/68

If the switch is not capable of capturing ingress and egress packets from a designated switch port for the purpose of remotely monitoring a specific user session, this is a finding.'
  desc 'fix', 'Enable the feature or configure the switch so that it is capable of capturing ingress and egress packets from any designated switch port for the purpose of monitoring a specific user session. The example configuration below will capture packets from interface Ethernet1/66 and replicate the packets to Ethernet1/68.

SW1(config)# monitor session 1
SW1(config-monitor)# source interface ethernet 1/66
SW1(config-monitor)# destination interface ethernet 1/68
SW1(config-monitor)# end'
  impact 0.5
  ref 'DPMS Target NX-OS L2 Switch'
  tag check_id: 'C-100107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-101227'
  tag rid: 'SV-110331r1_rule'
  tag stig_id: 'CISC-L2-000070'
  tag gtitle: 'SRG-NET-000332-L2S-000002'
  tag fix_id: 'F-106931r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001920']
  tag nist: ['AU-14 (3)']
end
