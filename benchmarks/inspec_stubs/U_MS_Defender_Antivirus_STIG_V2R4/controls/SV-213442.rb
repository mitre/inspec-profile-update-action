control 'SV-213442' do
  title 'Microsoft Defender AV must monitor for incoming and outgoing files.'
  desc 'This policy setting allows the configuration of monitoring for incoming and outgoing files without having to turn off monitoring entirely. It is recommended for use on servers that have a lot of incoming and outgoing file activity but for performance reasons need to have scanning disabled for a particular scan direction. The appropriate configuration should be evaluated based on the server role. Note that this configuration is only honored for NTFS volumes. For any other file system type, full monitoring of file and program activity will be present on those volumes. 

The options for this setting are mutually exclusive: 
0 = Scan incoming and outgoing files (default) 
1 = Scan incoming files only 
2 = Scan outgoing files only 

Any other value, or if the value does not exist, resolves to the default (0). If this setting is enabled, the specified type of monitoring will be enabled. If this setting is disabled or not configured, monitoring for incoming and outgoing files will be enabled.'
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Configure monitoring for incoming and outgoing file and program activity" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "RealtimeScanDirection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1 or 2, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Real-time Protection >> "Configure monitoring for incoming and outgoing file and program activity" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14667r820173_chk'
  tag severity: 'medium'
  tag gid: 'V-213442'
  tag rid: 'SV-213442r823056_rule'
  tag stig_id: 'WNDF-AV-000018'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14665r823055_fix'
  tag 'documentable'
  tag legacy: ['SV-89901', 'V-75221']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
