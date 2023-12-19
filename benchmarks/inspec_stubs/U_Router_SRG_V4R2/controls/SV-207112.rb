control 'SV-207112' do
  title 'The router must be configured to have all inactive interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the router configuration.

If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Delete inactive sub-interfaces and disable and delete the configuration of any inactive ports on the router.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7373r382229_chk'
  tag severity: 'low'
  tag gid: 'V-207112'
  tag rid: 'SV-207112r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000007'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7373r382230_fix'
  tag 'documentable'
  tag legacy: ['V-55731', 'SV-69985']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
