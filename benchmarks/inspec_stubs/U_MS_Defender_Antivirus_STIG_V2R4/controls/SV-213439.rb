control 'SV-213439' do
  title 'Microsoft Defender AV must be configured to not allow override of scanning for downloaded files and attachments.'
  desc 'This policy setting configures a local override for the configuration of scanning for all downloaded files and attachments. This setting can only be set by Group Policy. If this setting is enabled, the local preference setting will take priority over Group Policy. If this setting is disabled or not configured, Group Policy will take priority over the local preference setting.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Configure local setting override for scanning all downloaded files and attachments" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "LocalSettingOverrideDisableIOAVProtection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Configure local setting override for scanning all downloaded files and attachments" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14664r820164_chk'
  tag severity: 'medium'
  tag gid: 'V-213439'
  tag rid: 'SV-213439r823050_rule'
  tag stig_id: 'WNDF-AV-000015'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-14662r823049_fix'
  tag 'documentable'
  tag legacy: ['SV-89895', 'V-75215']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
