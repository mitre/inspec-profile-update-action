control 'SV-16948' do
  title 'The Recycle Bin on a server must be configured to immediately delete files.'
  desc 'The Recycle Bin saves a copy of a file when it is deleted.  A deleted file may contain sensitive data, subjecting that data to potential exposure.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_CURRENT_USER
Registry Path:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  NoRecycleFiles

Type:  REG_DWORD
Value:  1

If this is configured in the Recycle Bin Properties instead of through a policy verify the following:

Right Click the Recycle Bin and select Properties.
Select each Recycle Bin Location.
Verify that "Do not move files to the Recycle Bin. Remove files immediately when deleted." is selected. 

If any of the drives are not configured to delete files immediately, this is a finding.'
  desc 'fix', 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Windows Explorer -> "Do not move deleted files to the Recycle Bin" to "Enabled".

Or

Select "Do not move files to the Recycle Bin.  Remove files immediately when deleted." for each volume in the Recycle Bin Properties.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-51977r2_chk'
  tag severity: 'low'
  tag gid: 'V-1126'
  tag rid: 'SV-16948r2_rule'
  tag gtitle: 'Recycle Bin Configuration'
  tag fix_id: 'F-53857r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
