control 'SV-216646' do
  title 'The Cisco router must be configured to have all inactive interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the router configuration and verify that inactive interfaces have been disabled as shown below:

interface GigabitEthernet3
 shutdown
!
interface GigabitEthernet4
 shutdown
 
If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Disable all inactive interfaces as shown below:

R4(config)#interface GigabitEthernet3
R4(config-if)#shutdown
R4(config)#interface GigabitEthernet4
R4(config-if)#shutdown'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17879r287898_chk'
  tag severity: 'low'
  tag gid: 'V-216646'
  tag rid: 'SV-216646r531086_rule'
  tag stig_id: 'CISC-RT-000060'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-17877r287899_fix'
  tag 'documentable'
  tag legacy: ['SV-106003', 'V-96865']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
