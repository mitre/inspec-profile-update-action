control 'SV-220802' do
  title 'Insecure logons to an SMB server must be disabled.'
  desc 'Insecure guest logons allow unauthenticated access to shared folders.  Shared resources on a system must require authentication to establish proper access.'
  desc 'check', 'Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation\\

Value Name: AllowInsecureGuestAuth

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Lanman Workstation >> "Enable insecure guest logons" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22517r554891_chk'
  tag severity: 'medium'
  tag gid: 'V-220802'
  tag rid: 'SV-220802r569187_rule'
  tag stig_id: 'WN10-CC-000040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22506r554892_fix'
  tag 'documentable'
  tag legacy: ['V-63569', 'SV-78059']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
