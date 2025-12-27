control 'SV-33518' do
  title 'Read EMail as plain text must be enforced.'
  desc 'Outlook can display e-mail messages and other items in three formats: plain text, Rich Text Format (RTF), and HTML. By default, Outlook displays e-mail messages in whatever format they were received in.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> E-mail Options “Read e-mail as plain text” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value ReadAsPlain is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> E-mail Options “Read e-mail as plain text” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17770'
  tag rid: 'SV-33518r1_rule'
  tag stig_id: 'DTOO214 - Outlook'
  tag gtitle: 'DTOO214 - Read EMail as plain text'
  tag fix_id: 'F-29693r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
