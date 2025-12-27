control 'SV-85525' do
  title 'The ability to store user passwords in Skype must be disabled.'
  desc 'Allows Microsoft Lync to store user passwords. If you enable this policy setting, Microsoft Lync can store a password on request from the user. If you disable this policy setting, Microsoft Lync cannot store a password. If you do not configure this policy setting and the user logs on to a domain, Microsoft Lync does not store the password. If you do not configure this policy setting and the user does not log on to a domain (for example, if the user logs on to a workgroup), Microsoft Lync can store the password. Note: You can configure this policy setting under both Computer Configuration and User Configuration, but the policy setting under Computer Configuration takes precedence.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Skype for Business 2016 -> Microsoft Lync Feature Policies "Allow storage of user passwords" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\16.0\\lync

Criteria: If the value savepassword is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Skype for Business 2016 -> Microsoft Lync Feature Policies "Allow storage of user passwords" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Skype for Business 2016'
  tag check_id: 'C-71345r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70901'
  tag rid: 'SV-85525r1_rule'
  tag stig_id: 'DTOO420'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-77233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
