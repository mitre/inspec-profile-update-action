control 'SV-32453' do
  title 'Windows Update will be prevented from searching for point and print drivers.'
  desc 'This setting will prevent Windows from searching Windows Update for point and print drivers.  Only the local driver store and server driver cache will be searched.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name:  DoNotInstallCompatibleDriverFromWindowsUpdate

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Printers -> “Extend Point and Print connection to search Windows Update” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-26851r1_chk'
  tag severity: 'low'
  tag gid: 'V-21963'
  tag rid: 'SV-32453r1_rule'
  tag gtitle: 'Windows Update Point and Print Driver Search'
  tag fix_id: 'F-22950r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
