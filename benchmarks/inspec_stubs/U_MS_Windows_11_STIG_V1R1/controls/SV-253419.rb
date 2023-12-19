control 'SV-253419' do
  title 'The Windows Remote Management (WinRM) service must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowUnencryptedTraffic

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow unencrypted traffic" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56872r829339_chk'
  tag severity: 'medium'
  tag gid: 'V-253419'
  tag rid: 'SV-253419r829341_rule'
  tag stig_id: 'WN11-CC-000350'
  tag gtitle: 'SRG-OS-000394-GPOS-00174'
  tag fix_id: 'F-56822r829340_fix'
  tag 'documentable'
  tag cci: ['CCI-003093']
  tag nist: ['SA-3 d']
end
