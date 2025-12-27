control 'SV-228465' do
  title 'Hyperlinks in suspected phishing email messages must be disallowed.'
  desc 'This policy setting controls whether hyperlinks in suspected phishing e-mail messages in Outlook are allowed. If you enable this policy setting, Outlook will allow hyperlinks in suspected phishing messages that are not also classified as junk e-mail. If you disable or do not configure this policy setting, Outlook will not allow hyperlinks in suspected phishing messages, even if they are not classified as junk e-mail.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Trust Center "Allow hyperlinks in suspected phishing e-mail messages" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\mail

Criteria: If the value JunkMailEnableLinks is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Trust Center "Allow hyperlinks in suspected phishing e-mail messages" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30698r497717_chk'
  tag severity: 'medium'
  tag gid: 'V-228465'
  tag rid: 'SV-228465r508021_rule'
  tag stig_id: 'DTOO277'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30683r497718_fix'
  tag 'documentable'
  tag legacy: ['SV-85875', 'V-71251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
