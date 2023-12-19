control 'SV-85527' do
  title 'Session Initiation Protocol (SIP) security mode must be configured.'
  desc 'When Lync connects to the server, it supports various authentication mechanisms.  This policy allows the user to specify whether Digest and Basic authentication are supported.  Disabled (default):  NTLM/Kerberos/TLS-DSK/Digest/Basic     Enabled:  Authentication mechanisms:  NTLM/Kerberos/TLS-DSK  Gal Download: Requires HTTPS if user is not logged in as an internal user.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Skype for Business 2016 -> Microsoft Lync Feature Policies "Configure SIP security mode" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\16.0\\lync

Criteria: If the value enablesiphighsecuritymode is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Skype for Business 2016 -> Microsoft Lync Feature Policies "Configure SIP security mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Skype for Business 2016'
  tag check_id: 'C-71347r2_chk'
  tag severity: 'medium'
  tag gid: 'V-70903'
  tag rid: 'SV-85527r1_rule'
  tag stig_id: 'DTOO421'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-77235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
