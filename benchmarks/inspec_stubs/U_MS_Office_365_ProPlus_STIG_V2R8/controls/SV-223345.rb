control 'SV-223345' do
  title 'The HTTP fallback for SIP connection in Lync must be disabled.'
  desc 'Prevents from HTTP being used for SIP connection in case TLS or TCP fail.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Skype for Business 2016 >> Microsoft Lync Feature Policies "Disable HTTP fallback for SIP connection" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\16.0\\lync

If the value disablehttpconnect is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Skype for Business 2016 >> Microsoft Lync Feature Policies "Disable HTTP fallback for SIP connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25018r442254_chk'
  tag severity: 'medium'
  tag gid: 'V-223345'
  tag rid: 'SV-223345r879636_rule'
  tag stig_id: 'O365-LY-000002'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-25006r442255_fix'
  tag 'documentable'
  tag legacy: ['SV-108869', 'V-99765']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
