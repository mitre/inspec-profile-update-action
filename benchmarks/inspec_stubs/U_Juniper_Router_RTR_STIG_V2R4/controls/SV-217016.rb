control 'SV-217016' do
  title 'The Juniper router must be configured to have all inactive interfaces disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.

If an interface is no longer used, the configuration must be deleted and the interface disabled. For sub-interfaces, delete sub-interfaces that are on inactive interfaces and delete sub-interfaces that are themselves inactive. If the sub-interface is no longer necessary for authorized communications, it must be deleted.'
  desc 'check', 'Review the router configuration and verify that inactive interfaces have been disabled as shown below.

interfaces {
    ge-1/1/0  {
        disable;
        unit 0 {
        }
    }

If an interface is not being used but is configured or enabled, this is a finding.'
  desc 'fix', 'Disable all inactive interfaces as shown below.

[edit interfaces]
set ge-1/1/0 disable'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18245r296916_chk'
  tag severity: 'low'
  tag gid: 'V-217016'
  tag rid: 'SV-217016r604135_rule'
  tag stig_id: 'JUNI-RT-000060'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-18243r296917_fix'
  tag 'documentable'
  tag legacy: ['SV-101027', 'V-90817']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
