control 'SV-223344' do
  title 'The SIP security mode in Lync must be enabled.'
  desc 'When Lync connects to the server, it supports various authentication mechanisms. This policy allows the user to specify whether Digest and Basic authentication are supported. Disabled (default): NTLM/Kerberos/TLS-DSK/Digest/Basic Enabled: Authentication mechanisms: NTLM/Kerberos/TLS-DSK Gal Download: Requires HTTPS if user is not logged in as an internal user.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Skype for Business 2016 >> Microsoft Lync Feature Policies "Configure SIP security mode" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\16.0\\lync

If the value enablesiphighsecuritymode is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Skype for Business 2016 >> Microsoft Lync Feature Policies "Configure SIP security mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25017r442251_chk'
  tag severity: 'medium'
  tag gid: 'V-223344'
  tag rid: 'SV-223344r879636_rule'
  tag stig_id: 'O365-LY-000001'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-25005r442252_fix'
  tag 'documentable'
  tag legacy: ['SV-108867', 'V-99763']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
