control 'SV-83437' do
  title 'Data Execution Prevention (DEP) must be configured to at least OptOut.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications. Data Execution Prevention (DEP) prevents harmful code from running in protected memory locations reserved for Windows and other programs.'
  desc 'check', 'If DEP is configured through the Enhanced Mitigation Experience Toolkit (EMET) (V-36705), this is NA.

Verify the DEP configuration.
Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
Enter "BCDEdit /enum {current}". (If using PowerShell "{current}" must be enclosed in quotes.)
If the value for "nx" is not "OptOut", this is a finding.
(The more restrictive configuration of "AlwaysOn" would not be a finding.)'
  desc 'fix', 'Configure DEP to at least OptOut.

Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
Enter "BCDEDIT /set {current} nx OptOut".  (If using PowerShell "{current}" must be enclosed in quotes.)
"AlwaysOn", a more restrictive selection, is also valid but does not allow applications that do not function properly to be opted out of DEP.

Note: Suspend BitLocker before making changes to the DEP configuration.

Opted out exceptions can be configured in the "System Properties".

Open "System" in Control Panel.
Select "Advanced system settings".
Click "Settings" in the "Performance" section.
Select the "Data Execution Prevention" tab.
Applications that are opted out are configured in the window below the selection "Turn on DEP for all programs and services except those I select:".'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-69313r3_chk'
  tag severity: 'high'
  tag gid: 'V-68843'
  tag rid: 'SV-83437r1_rule'
  tag stig_id: 'WIN00-000145'
  tag gtitle: 'WIN00-000145'
  tag fix_id: 'F-75015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
