control 'SV-225519' do
  title 'Windows must elevate all applications in User Account Control, not just signed ones.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures whether Windows elevates all applications, or only signed ones.'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ValidateAdminCodeSignatures

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Only elevate executables that are signed and validated" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27218r471899_chk'
  tag severity: 'medium'
  tag gid: 'V-225519'
  tag rid: 'SV-225519r569185_rule'
  tag stig_id: 'WN12-SO-000081'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27206r471900_fix'
  tag 'documentable'
  tag legacy: ['V-16008', 'SV-53142']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
