control 'SV-103327' do
  title 'Windows Server 2019 insecure logons to an SMB server must be disabled.'
  desc 'Insecure guest logons allow unauthenticated access to shared folders. Shared resources on a system must require authentication to establish proper access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation\\

Value Name: AllowInsecureGuestAuth

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Lanman Workstation >> "Enable insecure guest logons" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92557r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93239'
  tag rid: 'SV-103327r1_rule'
  tag stig_id: 'WN19-CC-000070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-99485r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
