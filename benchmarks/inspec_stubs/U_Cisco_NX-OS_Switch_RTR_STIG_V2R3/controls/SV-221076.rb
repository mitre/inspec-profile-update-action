control 'SV-221076' do
  title 'The Cisco switch must be configured to have all inactive layer 3 interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a switch by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the switch configuration and verify that inactive interfaces have been disabled as shown below:

interface Ethernet4/12
 shutdown
 no switchport

interface Ethernet4/13
 shutdown
 no switchport
…
…
…
interface Ethernet4/48
 shutdown
 no switchport

If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Disable all inactive interfaces as shown below:

SW1(config)# int e4/1 - 11
SW1(config-if-range)# shutdown
SW1(config-if-range)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22791r409717_chk'
  tag severity: 'low'
  tag gid: 'V-221076'
  tag rid: 'SV-221076r622190_rule'
  tag stig_id: 'CISC-RT-000060'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-22780r409718_fix'
  tag 'documentable'
  tag legacy: ['SV-110971', 'V-101867']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
