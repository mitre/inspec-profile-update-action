control 'SV-254345' do
  title 'Windows Server 2022 group policy objects must be reprocessed even if they have not changed.'
  desc 'Registry entries for group policy settings can potentially be changed from the required configuration. This could occur as part of troubleshooting or by a malicious process on a compromised system. Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures the policies will be reprocessed even if none have been changed. This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\\

Value Name: NoGPOListChanges

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Group Policy >> Configure registry policy processing to "Enabled" with the option "Process even if the Group Policy objects have not changed" selected.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57830r848849_chk'
  tag severity: 'medium'
  tag gid: 'V-254345'
  tag rid: 'SV-254345r848851_rule'
  tag stig_id: 'WN22-CC-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57781r848850_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
