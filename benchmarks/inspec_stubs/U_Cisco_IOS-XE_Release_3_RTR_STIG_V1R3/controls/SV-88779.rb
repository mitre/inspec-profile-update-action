control 'SV-88779' do
  title 'The Cisco IOS XE router must be configured so inactive   interfaces are disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled.  For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive.  If the sub-interface is no longer necessary for authorized communications, then it must be deleted.'
  desc 'check', 'View the configuration of the Cisco IOS XE router. The configuration should look similar to the example below:

interface GigabitEthernet0/0/0
 no ip address
 shutdown

If an interface is not being used, but is configured or enabled, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router so that all inactive sub-interfaces are deleted, and disable and delete the configuration of any inactive ports on the router. To shut down an interface see the following commands:

ISR4000(config) #Interface GigabitEthernet 0/0/1
ISR4000(config-if) #shutdown

To clear the configuration of an inactive interface, use the following command:

ISR4000 (config) #default interface GigabitEthernet 0/0/1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74191r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74105'
  tag rid: 'SV-88779r2_rule'
  tag stig_id: 'CISR-RT-000005'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-80647r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
