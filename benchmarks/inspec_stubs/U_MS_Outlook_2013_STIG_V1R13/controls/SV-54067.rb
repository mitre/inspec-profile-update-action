control 'SV-54067' do
  title 'Outlook Rich Text options must be set for converting to plain text format.'
  desc 'Outlook automatically converts RTF formatted messages that are sent over the Internet to HTML format, so that the message formatting is maintained and attachments are received.
This setting controls how Outlook sends Rich Text Format (RTF) messages to Internet recipients.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Mail Format -> Internet Formatting "Outlook Rich Text options" is "Enabled: Convert to Plain Text format".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail

Criteria: If the value Message RTF Format is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Mail Format -> Internet Formatting "Outlook Rich Text options" to "Enabled: Convert to Plain Text format".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-48007r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26633'
  tag rid: 'SV-54067r1_rule'
  tag stig_id: 'DTOO344'
  tag gtitle: 'DTOO344 - Outlook Rich Text options'
  tag fix_id: 'F-46947r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
