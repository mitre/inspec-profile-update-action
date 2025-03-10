control 'SV-256001' do
  title 'The Arista router must be configured to have all inactive interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the Arista router configuration.

Verify the interfaces and sub-interfaces execute the commands "show ip interface brief" and "show interface status".

Example of a disabled interface:
interface Ethernet 8-10
 description The interface is administratively shutdown
 shutdown

If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Delete inactive sub-interfaces and disable and delete the configuration of any inactive ports on the router.

Deleting the sub-interface:

router(config)#no interface Ethernet8.100

Disabling the interface:

router(config)#interface Ethernet 8-10
router(config-if-Et8-10)#shutdown

Resetting the interface to the default-configuration:

router(config)#default interface Ethernet 8'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59677r882343_chk'
  tag severity: 'low'
  tag gid: 'V-256001'
  tag rid: 'SV-256001r882345_rule'
  tag stig_id: 'ARST-RT-000150'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-59620r882344_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
