control 'SV-213439' do
  title 'Windows Defender AV must be configured to not allow override of scanning for downloaded files and attachments.'
  desc 'This policy setting configures a local override for the configuration of scanning for all downloaded files and attachments. This setting can only be set by Group Policy. If you enable this setting the local preference setting will take priority over Group Policy. If you disable or do not configure this setting Group Policy will take priority over the local preference setting.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override for scanning all downloaded files and attachments" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "LocalSettingOverrideDisableIOAVProtection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override for scanning all downloaded files and attachments" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14664r314626_chk'
  tag severity: 'medium'
  tag gid: 'V-213439'
  tag rid: 'SV-213439r569189_rule'
  tag stig_id: 'WNDF-AV-000015'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-14662r314627_fix'
  tag 'documentable'
  tag legacy: ['SV-89895', 'V-75215']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
