control 'SV-253424' do
  title 'Windows Ink Workspace must be configured to disallow access above the lock.'
  desc 'This action secures Windows Ink, which contains applications and features oriented toward pen computing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\WindowsInkWorkspace

Value Name: AllowWindowsInkWorkspace
Value Type: REG_DWORD
Value data: 1'
  desc 'fix', 'Disable the convenience PIN sign-in. 

To correct this, configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Ink Workspace >> Set "Allow Windows Ink Workspace" to "Enabled and set Options "On, but disallow access above lock".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56877r829354_chk'
  tag severity: 'medium'
  tag gid: 'V-253424'
  tag rid: 'SV-253424r829356_rule'
  tag stig_id: 'WN11-CC-000385'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-56827r829355_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
