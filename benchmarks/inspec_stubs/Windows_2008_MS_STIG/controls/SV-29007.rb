control 'SV-29007' do
  title 'Automatic logons must be disabled.'
  desc 'Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options.

If the value for "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" is not set to "Disabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: AutoAdminLogon

Type: REG_SZ
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".

Ensure no passwords are stored in the "DefaultPassword" registry value noted below.

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: DefaultPassword'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-45834r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1145'
  tag rid: 'SV-29007r2_rule'
  tag gtitle: 'Disable Automatic Logon'
  tag fix_id: 'F-43225r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If the DefaultName or DefaultDomainName in the same registry path contain an administrator account name and the DefaultPassword contains a value, this is a CAT I finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
