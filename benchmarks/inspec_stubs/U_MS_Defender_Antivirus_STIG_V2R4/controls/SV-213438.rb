control 'SV-213438' do
  title 'Microsoft Defender AV must be configured to not allow override of monitoring for incoming and outgoing file activity.'
  desc 'This policy setting configures a local override for the configuration of monitoring for incoming and outgoing file activity. This setting can only be set by Group Policy. If this setting is enabled, the local preference setting will take priority over Group Policy. If this setting is disabled or not configured, Group Policy will take priority over the local preference setting.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Configure local setting override for monitoring for incoming and outgoing file activity" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "LocalSettingOverrideRealtimeScanDirection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Configure local setting override for monitoring for incoming and outgoing file activity" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14663r820161_chk'
  tag severity: 'medium'
  tag gid: 'V-213438'
  tag rid: 'SV-213438r823048_rule'
  tag stig_id: 'WNDF-AV-000014'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-14661r823047_fix'
  tag 'documentable'
  tag legacy: ['SV-89893', 'V-75213']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
