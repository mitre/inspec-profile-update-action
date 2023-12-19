control 'SV-29006' do
  title 'Automatic logons must be disabled.'
  desc 'Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".

Ensure no passwords are stored in the "DefaultPassword" registry value noted below.

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: DefaultPassword'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1145'
  tag rid: 'SV-29006r2_rule'
  tag gtitle: 'Disable Automatic Logon'
  tag fix_id: 'F-43224r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If the DefaultName or DefaultDomainName in the same registry path contain an administrator account name and the DefaultPassword contains a value, this is a CAT I finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
