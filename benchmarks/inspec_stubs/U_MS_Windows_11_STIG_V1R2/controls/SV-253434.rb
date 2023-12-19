control 'SV-253434' do
  title 'Local accounts with blank passwords must be restricted to prevent access from the network.'
  desc 'An account without a password can allow unauthorized access to a system as only the username would be required. Password policies must prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password did exist, enabling this setting will prevent network access, limiting the account to local console logon only.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: LimitBlankPasswordUse

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Limit local account use of blank passwords to console logon only" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56887r829384_chk'
  tag severity: 'medium'
  tag gid: 'V-253434'
  tag rid: 'SV-253434r829386_rule'
  tag stig_id: 'WN11-SO-000015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56837r829385_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
