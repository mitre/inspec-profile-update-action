control 'SV-226301' do
  title 'Automatic logons must be disabled.'
  desc 'Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: AutoAdminLogon

Type: REG_SZ
Value: 0'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".

Ensure no passwords are stored in the "DefaultPassword" registry value noted below:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: DefaultPassword

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

Severity Override Guidance: If the DefaultName or DefaultDomainName in the same registry path contain an administrator account name and the DefaultPassword contains a value, this is a CAT I finding.)
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28003r476747_chk'
  tag severity: 'medium'
  tag gid: 'V-226301'
  tag rid: 'SV-226301r794593_rule'
  tag stig_id: 'WN12-SO-000036'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27991r794592_fix'
  tag 'documentable'
  tag legacy: ['SV-52107', 'V-1145']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
