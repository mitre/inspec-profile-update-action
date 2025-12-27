control 'SV-82725' do
  title 'The Mainframe Product must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'If the Mainframe Product has no function or capability for session operations, this is not applicable.

Examine installation and configuration settings.

Verify that session auditing is initiated at session startup. If it is not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to initiate session auditing upon startup.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68235'
  tag rid: 'SV-82725r1_rule'
  tag stig_id: 'SRG-APP-000092-MFP-000137'
  tag gtitle: 'SRG-APP-000092-MFP-000137'
  tag fix_id: 'F-74349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
