control 'SV-34105' do
  title 'Default message format must be set to use Plain Text.'
  desc 'Outlook uses HTML as the default e-mail format, but users can choose a format other than the default when composing messages. This setting controls the default message format in Outlook.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail Format -> Internet Formatting -> Message Format “Set message format” must be “Enabled: Plain Text".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value EditorPreference is REG_DWORD = 65536 (dec), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Mail Format -> Internet Formatting -> Message Format “Set message format” to “Enabled: Plain Text".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34230r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26634'
  tag rid: 'SV-34105r1_rule'
  tag stig_id: 'DTOO314 - Outlook'
  tag gtitle: 'DTOO314 - Set message format'
  tag fix_id: 'F-29920r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
