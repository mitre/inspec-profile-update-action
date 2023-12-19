control 'SV-3344' do
  title 'The use of local accounts with blank passwords is not restricted to console logons only.'
  desc 'This is a Category 1 finding because no accounts with blank passwords should exist on a system.  The password policy should prevent this from occurring.  However, if a local account with a blank password does exist, enabling this setting will limit the account to local console logon only.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies -> Security Options.

If the value for “Accounts: Limit local account use of blank passwords to console logon only” is not set to ” Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa

Value Name:  LimitBlankPasswordUse

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Accounts: Limit local account use of blank passwords to console logon only” to “Enabled”.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-475r1_chk'
  tag severity: 'high'
  tag gid: 'V-3344'
  tag rid: 'SV-3344r1_rule'
  tag gtitle: 'Limit Blank Passwords'
  tag fix_id: 'F-5788r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1'
end
