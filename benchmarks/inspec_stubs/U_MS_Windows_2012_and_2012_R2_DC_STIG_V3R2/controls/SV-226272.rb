control 'SV-226272' do
  title 'Local accounts with blank passwords must be restricted to prevent access from the network.'
  desc 'An account without a password can allow unauthorized access to a system as only the username would be required.  Password policies should prevent accounts with blank passwords from existing on a system.  However, if a local account with a blank password did exist, enabling this setting will prevent network access, limiting the account to local console logon only.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Limit local account use of blank passwords to console logon only" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27974r476660_chk'
  tag severity: 'high'
  tag gid: 'V-226272'
  tag rid: 'SV-226272r569184_rule'
  tag stig_id: 'WN12-SO-000004'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27962r476661_fix'
  tag 'documentable'
  tag legacy: ['SV-52886', 'V-3344']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
