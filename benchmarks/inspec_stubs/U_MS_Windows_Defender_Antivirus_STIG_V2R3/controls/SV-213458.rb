control 'SV-213458' do
  title 'Windows Defender AV must be configured block Office applications from creating executable content.'
  desc 'This rule targets typical behaviors used by suspicious and malicious add-ons and scripts (extensions) that create or launch executable files. This is a typical malware technique.
Extensions will be blocked from being used by Office apps. Typically these extensions use the Windows Scripting Host (.wsh files) to run scripts that automate certain tasks or provide user-created add-on features.'
  desc 'check', 'This setting is applicable starting with v1709 of Windows 10, it is NA for prior versions.

Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Windows Defender Exploit Guard -> Attack Surface Reduction -> "Configure Attack Surface Reduction rules" is set to "Enabled”.  Click ‘Show...’.  Verify the rule ID in the Value name column and the desired state in the Value column is set as follows:
Value name: 3B576869-A4EC-4529-8536-B80A7769E899
Value:  1
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules

Criteria: If the value “3B576869-A4EC-4529-8536-B80A7769E899” is REG_SZ = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Windows Defender Exploit Guard -> Attack Surface Reduction -> "Configure Attack Surface Reduction rules" to "Enabled”.   Click ‘Show...’.  Set the Value name to “3B576869-A4EC-4529-8536-B80A7769E899” and the Value to “1”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14683r314683_chk'
  tag severity: 'medium'
  tag gid: 'V-213458'
  tag rid: 'SV-213458r569189_rule'
  tag stig_id: 'WNDF-AV-000034'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14681r314684_fix'
  tag 'documentable'
  tag legacy: ['SV-92665', 'V-77969']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
