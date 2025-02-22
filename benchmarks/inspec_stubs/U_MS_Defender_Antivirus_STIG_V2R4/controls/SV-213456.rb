control 'SV-213456' do
  title 'Microsoft Defender AV must be configured to block executable content from email client and webmail.'
  desc 'This rule blocks the following file types from being run or launched from an email seen in either Microsoft Outlook or webmail (such as Gmail.com or Outlook.com):
Executable files (such as .exe, .dll, or .scr)
Script files (such as a PowerShell .ps, VisualBasic .vbs, or JavaScript .js file)
Script archive files'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10. It is NA for prior versions.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" is set to "Enabled”.  Click "Show...". Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550
Value:  1

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" to "Enabled". 

Click "Show...". Set the Value name to "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" and the Value to "1".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14681r820215_chk'
  tag severity: 'medium'
  tag gid: 'V-213456'
  tag rid: 'SV-213456r823081_rule'
  tag stig_id: 'WNDF-AV-000032'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14679r823080_fix'
  tag 'documentable'
  tag legacy: ['SV-92661', 'V-77965']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
