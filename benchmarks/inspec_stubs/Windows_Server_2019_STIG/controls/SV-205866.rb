control 'SV-205866' do
  title 'Windows Server 2019 group policy objects must be reprocessed even if they have not changed.'
  desc 'Registry entries for group policy settings can potentially be changed from the required configuration. This could occur as part of troubleshooting or by a malicious process on a compromised system. Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\\

Value Name: NoGPOListChanges

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Group Policy >> "Configure registry policy processing" to "Enabled" with the option "Process even if the Group Policy objects have not changed" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6131r355960_chk'
  tag severity: 'medium'
  tag gid: 'V-205866'
  tag rid: 'SV-205866r569188_rule'
  tag stig_id: 'WN19-CC-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6131r355961_fix'
  tag 'documentable'
  tag legacy: ['V-93251', 'SV-103339']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
