control 'SV-48036' do
  title 'The built-in administrator account must be renamed.'
  desc 'The built-in administrator account is a well-known account subject to attack.  Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for "Accounts: Rename administrator account" is not set to a value other than "Administrator", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Accounts: Rename administrator account" to a name other than "Administrator".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44774r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1115'
  tag rid: 'SV-48036r1_rule'
  tag stig_id: 'WN08-SO-000005'
  tag gtitle: 'Rename Built-in Administrator Account'
  tag fix_id: 'F-41174r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
