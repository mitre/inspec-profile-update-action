control 'SV-213444' do
  title 'Microsoft Defender AV must be configured to scan all downloaded files and attachments.'
  desc 'This policy setting allows configuration of scanning for all downloaded files and attachments. If this setting is enabled or not configured, scanning for all downloaded files and attachments will be enabled. If this setting is disabled, scanning for all downloaded files and attachments will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Scan all downloaded files and attachments" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableIOAVProtection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Scan all downloaded files and attachments" to "Enabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14669r820179_chk'
  tag severity: 'medium'
  tag gid: 'V-213444'
  tag rid: 'SV-213444r823060_rule'
  tag stig_id: 'WNDF-AV-000020'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-14667r823059_fix'
  tag 'documentable'
  tag legacy: ['SV-89905', 'V-75225']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
