control 'SV-251867' do
  title 'Outlook Rich Text options must be set for converting to plain text format.'
  desc 'Outlook automatically converts Rich Text Format (RTF) messages that are sent over the internet to HTML format, so that the message formatting is maintained and attachments are received.
This setting controls how Outlook sends RTF messages to internet recipients.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Mail Format >> Internet Formatting "Outlook Rich Text options" is "Enabled: Convert to Plain Text format".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value Message RTF Format is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Mail Format >> Internet Formatting "Outlook Rich Text options" to "Enabled: Convert to Plain Text format".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-55327r811190_chk'
  tag severity: 'medium'
  tag gid: 'V-251867'
  tag rid: 'SV-251867r812967_rule'
  tag stig_id: 'DTOO344'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-55281r811191_fix'
  tag 'documentable'
  tag legacy: ['SV-57685', 'V-44851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
