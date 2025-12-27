control 'SV-226341' do
  title 'User Account Control must be configured to detect application installations and prompt for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting requires Windows to respond to application installation requests by prompting for credentials.'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableInstallerDetection

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Detect application installations and prompt for elevation" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28043r476867_chk'
  tag severity: 'medium'
  tag gid: 'V-226341'
  tag rid: 'SV-226341r569184_rule'
  tag stig_id: 'WN12-SO-000080'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-28031r476868_fix'
  tag 'documentable'
  tag legacy: ['V-14237', 'SV-52949']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
