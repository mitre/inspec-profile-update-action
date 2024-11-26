control 'SV-220424' do
  title 'The Cisco switch must be configured to have all inactive Layer 3 interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a switch by connecting to a configured interface that is not in use. 

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the switch configuration and verify that inactive interfaces have been disabled as shown below: 

interface GigabitEthernet3 
 no switchport 
 shutdown 
! 
interface GigabitEthernet4 
 no switchport 
 shutdown 

If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Disable all inactive interfaces as shown below: 

SW1(config)#interface GigabitEthernet3 
SW1(config-if)#shutdown 
SW1(config)#interface GigabitEthernet4 
SW1(config-if)#shutdown'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22139r508360_chk'
  tag severity: 'low'
  tag gid: 'V-220424'
  tag rid: 'SV-220424r622190_rule'
  tag stig_id: 'CISC-RT-000060'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-22128r508361_fix'
  tag 'documentable'
  tag legacy: ['SV-110695', 'V-101591']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
