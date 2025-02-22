control 'SV-48073' do
  title 'Local accounts with blank passwords must be restricted to prevent access from the network.'
  desc 'An account without a password can allow unauthorized access to a system as only the username would be required.  Password policies should prevent accounts with blank passwords from existing on a system.  However, if a local account with a blank password did exist, enabling this setting will prevent network access, limiting the account to local console logon only.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Accounts: Limit local account use of blank passwords to console logon only" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Limit local account use of blank passwords to console logon only" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44812r1_chk'
  tag severity: 'high'
  tag gid: 'V-3344'
  tag rid: 'SV-48073r1_rule'
  tag stig_id: 'WN08-SO-000004'
  tag gtitle: 'Limit Blank Passwords'
  tag fix_id: 'F-41211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
