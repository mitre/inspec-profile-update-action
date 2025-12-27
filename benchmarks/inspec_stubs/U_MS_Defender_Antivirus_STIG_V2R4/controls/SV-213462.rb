control 'SV-213462' do
  title 'Microsoft Defender AV must be configured to block Win32 imports from macro code in Office.'
  desc 'This rule blocks potentially malicious behavior by not allowing macro code to execute routines in the Win 32 dynamic link library (DLL).'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10. It is NA for prior versions.

Verify the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Microsoft Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" is set to "Enabled". Click "Show...". Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B
Value:  1

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Defender Antivirus >> Windows Defender Exploit Guard >> Attack Surface Reduction >> "Configure Attack Surface Reduction rules" to "Enabled". 

Click "Show...". Set the Value name to "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" and the Value to "1".'
  impact 0.5
  ref 'DPMS Target Microsoft Defender Antivirus'
  tag check_id: 'C-14687r820233_chk'
  tag severity: 'medium'
  tag gid: 'V-213462'
  tag rid: 'SV-213462r823093_rule'
  tag stig_id: 'WNDF-AV-000038'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14685r823092_fix'
  tag 'documentable'
  tag legacy: ['SV-92673', 'V-77977']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
