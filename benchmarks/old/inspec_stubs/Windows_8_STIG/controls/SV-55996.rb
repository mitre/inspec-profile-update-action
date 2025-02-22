control 'SV-55996' do
  title 'The use of OneDrive for storage must be disabled.'
  desc 'OneDrive provides access to external services for data storage which must not be used. Enabling this setting will prevent such access from the OneDrive app, as well as from File Explorer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Skydrive\\

Value Name: DisableFileSync

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> OneDrive >> "Prevent the usage of OneDrive for file storage" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-66273r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43243'
  tag rid: 'SV-55996r4_rule'
  tag stig_id: 'WN08-CC-000143'
  tag gtitle: 'WINCC-000143'
  tag fix_id: 'F-76995r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
