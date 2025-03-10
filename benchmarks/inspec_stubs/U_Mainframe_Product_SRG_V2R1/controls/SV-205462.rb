control 'SV-205462' do
  title 'The Mainframe Product must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'If the Mainframe Product has no function or capability for session operations, this is not applicable.

Examine installation and configuration settings.

Verify that session auditing is initiated at session startup. If it is not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to initiate session auditing upon startup.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5728r299619_chk'
  tag severity: 'medium'
  tag gid: 'V-205462'
  tag rid: 'SV-205462r395715_rule'
  tag stig_id: 'SRG-APP-000092-MFP-000137'
  tag gtitle: 'SRG-APP-000092'
  tag fix_id: 'F-5728r299620_fix'
  tag 'documentable'
  tag legacy: ['SV-82725', 'V-68235']
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
