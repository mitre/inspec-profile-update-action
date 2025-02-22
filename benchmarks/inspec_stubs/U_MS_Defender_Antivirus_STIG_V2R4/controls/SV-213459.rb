control 'SV-213459' do
  title 'Microsoft Defender AV must be configured to block Office applications from injecting into other processes.'
  desc 'Office apps, such as Word, Excel, or PowerPoint, will not be able to inject code into other processes. This is typically used by malware to run malicious code in an attempt to hide the activity from antivirus scanning engines.'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10. It is NA for prior versions.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" is set to "Enabled”.  Click "Show...". Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
Value:  1

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" to "Enabled".

Click "Show...". Set the Value name to "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" and the Value to "1".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14684r820224_chk'
  tag severity: 'medium'
  tag gid: 'V-213459'
  tag rid: 'SV-213459r823087_rule'
  tag stig_id: 'WNDF-AV-000035'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14682r823086_fix'
  tag 'documentable'
  tag legacy: ['SV-92667', 'V-77971']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
