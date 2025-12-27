control 'SV-85529' do
  title 'In the event a secure Session Initiation Protocol (SIP) connection fails, the connection must be restricted from resorting to the unencrypted HTTP.'
  desc 'Prevents from HTTP being used for SIP connection in case TLS or TCP fail.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Skype for Business 2016 -> Microsoft Lync Feature Policies "Disable HTTP fallback for SIP connection" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\Software\\Policies\\Microsoft\\office\\16.0\\lync

Criteria: If the value disablehttpconnect is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Skype for Business 2016 -> Microsoft Lync Feature Policies "Disable HTTP fallback for SIP connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Skype for Business 2016'
  tag check_id: 'C-71349r3_chk'
  tag severity: 'medium'
  tag gid: 'V-70905'
  tag rid: 'SV-85529r1_rule'
  tag stig_id: 'DTOO422'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-77237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
