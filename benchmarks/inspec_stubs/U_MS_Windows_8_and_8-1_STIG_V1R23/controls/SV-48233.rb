control 'SV-48233' do
  title 'Non-administrators must be prevented from applying vendor-signed updates.'
  desc 'Uncontrolled system updates can introduce issues to a system.  This setting will prevent users from applying vendor-signed updates (though they may be from a trusted source).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: DisableLUAPatching

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prohibit non-administrators from applying vendor signed updates" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44912r1_chk'
  tag severity: 'low'
  tag gid: 'V-15686'
  tag rid: 'SV-48233r1_rule'
  tag stig_id: 'WN08-CC-000118'
  tag gtitle: 'Windows Installer – Vendor Signed Updates'
  tag fix_id: 'F-41369r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
