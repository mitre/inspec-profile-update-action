control 'SV-75353' do
  title 'The Arista Multilayer Switch must be configured so inactive router interfaces are disabled.'
  desc 'An inactive interface is rarely monitored or controlled and may expose a network to an undetected attack on that interface. Unauthorized personnel with access to the communication facility could gain access to a router by connecting to a configured interface that is not in use.'
  desc 'check', 'Verify inactive interfaces on the router are disabled by executing a "show interface status" command and confirming the line "disabled" is present on any interface where the interface is inactive.

If there are any inactive interfaces enabled on the router, this is a finding.'
  desc 'fix', 'Remove subinterfaces and disable any inactive ports on the router via the "shutdown" command on the interface configuration mode.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60895'
  tag rid: 'SV-75353r1_rule'
  tag stig_id: 'AMLS-L3-000140'
  tag gtitle: 'SRG-NET-000019-RTR-000007'
  tag fix_id: 'F-66607r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
