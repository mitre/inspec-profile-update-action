control 'SV-225520' do
  title 'User Account Control must only elevate UIAccess applications that are installed in secure locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\\System32 folders, to run with elevated privileges.'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableSecureUIAPaths

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27219r471902_chk'
  tag severity: 'medium'
  tag gid: 'V-225520'
  tag rid: 'SV-225520r569185_rule'
  tag stig_id: 'WN12-SO-000082'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-27207r471903_fix'
  tag 'documentable'
  tag legacy: ['V-14239', 'SV-52950']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
