control 'SV-213457' do
  title 'Windows Defender AV must be configured block Office applications from creating child processes.'
  desc 'Office apps, such as Word or Excel, will not be allowed to create child processes.
This is a typical malware behavior, especially for macro-based attacks that attempt to use Office apps to launch or download malicious executables.'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10, it is NA for prior versions.

Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Windows Defender Exploit Guard -> Attack Surface Reduction -> "Configure Attack Surface Reduction rules" is set to "Enabled”.  Click ‘Show...’.  Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: D4F940AB-401B-4EFC-AADC-AD5F3C50688A
Value:  1

Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value “D4F940AB-401B-4EFC-AADC-AD5F3C50688A” is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Windows Defender Exploit Guard -> Attack Surface Reduction -> "Configure Attack Surface Reduction rules" to "Enabled”.   Click ‘Show...’.  Set the Value name to “D4F940AB-401B-4EFC-AADC-AD5F3C50688A” and the Value to “1”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14682r314680_chk'
  tag severity: 'medium'
  tag gid: 'V-213457'
  tag rid: 'SV-213457r569189_rule'
  tag stig_id: 'WNDF-AV-000033'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14680r314681_fix'
  tag 'documentable'
  tag legacy: ['SV-92663', 'V-77967']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
