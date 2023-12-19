control 'SV-213461' do
  title 'Microsoft Defender AV must be configured to block execution of potentially obfuscated scripts.'
  desc 'Malware and other threats can attempt to obfuscate or hide their malicious code in some script files. This rule prevents scripts that appear to be obfuscated from running. It uses the AntiMalwareScanInterface (AMSI) to determine if a script is potentially obfuscated and then blocks such a script or blocks scripts when an attempt is made to access them.'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10. It is NA for prior versions.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" is set to "Enabled”.  Click "Show...". Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC
Value:  1

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" to "Enabled". 

Click "Show...". Set the Value name to "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" and the Value to "1".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14686r820230_chk'
  tag severity: 'medium'
  tag gid: 'V-213461'
  tag rid: 'SV-213461r823091_rule'
  tag stig_id: 'WNDF-AV-000037'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14684r823090_fix'
  tag 'documentable'
  tag legacy: ['SV-92671', 'V-77975']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
