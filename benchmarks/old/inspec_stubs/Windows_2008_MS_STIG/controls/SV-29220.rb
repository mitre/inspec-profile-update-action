control 'SV-29220' do
  title 'Users are not warned in advance that their passwords will expire.'
  desc 'This setting configures the system to display a warning to users telling them how many days are left before their password expires.  By giving the user advanced warning, the user has time to construct a sufficiently strong password.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Interactive Logon: Prompt user to change password before expiration” is not set to  “14" days or more, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  PasswordExpiryWarning

Value Type:  REG_DWORD
Value:  14'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive Logon: Prompt user to change password before expiration” to “14” days or more.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-137r1_chk'
  tag severity: 'low'
  tag gid: 'V-1172'
  tag rid: 'SV-29220r1_rule'
  tag gtitle: 'Password Expiration Warning'
  tag fix_id: 'F-114r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
