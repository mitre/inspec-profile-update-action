control 'SV-251865' do
  title 'Read signed email as plain text must be enforced.'
  desc 'Outlook can display email messages and other items in three formats: plain text, Rich Text Format (RTF), and HTML. By default, Outlook displays digitally signed email messages in the format which they were received.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Preferences >> E-mail Options "Read signed e-mail as plain text" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value ReadSignedAsPlain is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Preferences >> E-mail Options "Read signed e-mail as plain text" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-55325r811184_chk'
  tag severity: 'medium'
  tag gid: 'V-251865'
  tag rid: 'SV-251865r811186_rule'
  tag stig_id: 'DTOO215'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-55279r811185_fix'
  tag 'documentable'
  tag legacy: ['SV-57685', 'V-44851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
