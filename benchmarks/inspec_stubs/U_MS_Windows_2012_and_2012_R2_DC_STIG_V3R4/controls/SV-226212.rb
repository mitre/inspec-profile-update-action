control 'SV-226212' do
  title 'Nonadministrators must be prevented from applying vendor-signed updates.'
  desc 'Uncontrolled system updates can introduce issues to a system.  This setting will prevent users from applying vendor-signed updates (though they may be from a trusted source).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: DisableLUAPatching

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prohibit non-administrators from applying vendor signed updates" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27914r475959_chk'
  tag severity: 'low'
  tag gid: 'V-226212'
  tag rid: 'SV-226212r794475_rule'
  tag stig_id: 'WN12-CC-000118'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27902r475960_fix'
  tag 'documentable'
  tag legacy: ['SV-53065', 'V-15686']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
