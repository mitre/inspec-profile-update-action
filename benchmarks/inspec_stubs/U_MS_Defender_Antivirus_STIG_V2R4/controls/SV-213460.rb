control 'SV-213460' do
  title 'Microsoft Defender AV must be configured to impede JavaScript and VBScript to launch executables.'
  desc 'JavaScript and VBScript scripts can be used by malware to launch other malicious apps. This rule prevents these scripts from being allowed to launch apps, thus preventing malicious use of the scripts to spread malware and infect machines.'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10. It is NA for prior versions.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" is set to "Enabled". Click "Show...". Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: D3E037E1-3EB8-44C8-A917-57927947596D 
Value:  1

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "D3E037E1-3EB8-44C8-A917-57927947596D" is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" to "Enabled".

Click "Show...". Set the Value name to "D3E037E1-3EB8-44C8-A917-57927947596D" and the Value to "1".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14685r820227_chk'
  tag severity: 'medium'
  tag gid: 'V-213460'
  tag rid: 'SV-213460r823089_rule'
  tag stig_id: 'WNDF-AV-000036'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14683r823088_fix'
  tag 'documentable'
  tag legacy: ['SV-92669', 'V-77973']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
