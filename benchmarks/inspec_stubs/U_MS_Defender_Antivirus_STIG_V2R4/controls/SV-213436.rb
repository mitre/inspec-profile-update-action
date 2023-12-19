control 'SV-213436' do
  title 'Microsoft Defender AV must be configured for protocol recognition for network protection.'
  desc 'This policy setting allows the configuration of protocol recognition for network protection against exploits of known vulnerabilities. If this setting is enabled or not configured, protocol recognition will be enabled. If this setting is disabled, protocol recognition will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Network Inspection System >> "Turn on protocol recognition" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\NIS

Criteria: If the value "DisableProtocolRecognition" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Network Inspection System >> "Turn on protocol recognition" to "Enabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14661r820155_chk'
  tag severity: 'medium'
  tag gid: 'V-213436'
  tag rid: 'SV-213436r823044_rule'
  tag stig_id: 'WNDF-AV-000012'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14659r823043_fix'
  tag 'documentable'
  tag legacy: ['SV-89889', 'V-75209']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
