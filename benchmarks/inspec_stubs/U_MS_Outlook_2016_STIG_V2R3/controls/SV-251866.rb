control 'SV-251866' do
  title 'The default message format must be set to use Plain Text.'
  desc 'Outlook uses HTML as the default email format. HTML format poses a security risk by embedding information into the email itself, which could allow for release of sensitive information. If a user attempted to insert an HTML link into an email message, the link itself may direct to a malicious website. By sending emails in HTML format, the recipient could be subject to becoming infected by the malicious website.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Mail Format >> Internet Formatting >> Message Format "Set message format" is "Enabled: Plain Text".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value EditorPreference is REG_DWORD = 65536 (dec), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Mail Format >> Internet Formatting >> Message Format "Set message format" to "Enabled: Plain Text".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-55326r811187_chk'
  tag severity: 'medium'
  tag gid: 'V-251866'
  tag rid: 'SV-251866r811197_rule'
  tag stig_id: 'DTOO314'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-55280r811188_fix'
  tag 'documentable'
  tag legacy: ['SV-57685', 'V-44851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
