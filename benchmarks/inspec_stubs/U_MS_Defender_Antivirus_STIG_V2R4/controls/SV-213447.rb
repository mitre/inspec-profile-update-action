control 'SV-213447' do
  title 'Microsoft Defender AV must be configured to process scanning when real-time protection is enabled.'
  desc 'This policy setting allows the configuration of process scanning when real-time protection is turned on. This helps to catch malware, which could start when real-time protection is turned off. If this setting is enabled or not configured, a process scan will be initiated when real-time protection is turned on. If this setting is disabled, a process scan will not be initiated when real-time protection is turned on.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Turn on process scanning whenever real-time protection is enabled" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableScanOnRealtimeEnable" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Turn on process scanning whenever real-time protection is enabled" to "Enabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14672r820188_chk'
  tag severity: 'medium'
  tag gid: 'V-213447'
  tag rid: 'SV-213447r823065_rule'
  tag stig_id: 'WNDF-AV-000023'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14670r823064_fix'
  tag 'documentable'
  tag legacy: ['SV-89911', 'V-75231']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
