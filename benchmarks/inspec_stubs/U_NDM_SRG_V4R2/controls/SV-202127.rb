control 'SV-202127' do
  title 'The network device must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Check the network device configuration to determine if the device off-loads audit records onto a different system or media than the system being audited.

If the device does not off-load audit records onto a different system or media, this is a finding.'
  desc 'fix', 'Configure the network device to off-load audit records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2253r382061_chk'
  tag severity: 'medium'
  tag gid: 'V-202127'
  tag rid: 'SV-202127r879886_rule'
  tag stig_id: 'SRG-APP-000515-NDM-000325'
  tag gtitle: 'SRG-APP-000515'
  tag fix_id: 'F-2254r382062_fix'
  tag 'documentable'
  tag legacy: ['SV-69533', 'V-55287']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
