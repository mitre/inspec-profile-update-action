control 'SV-1115' do
  title 'The built-in administrator account has not been renamed.'
  desc 'The built-in administrator account is a well known account.  Renaming the account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Accounts: Rename administrator account” is not set to a value other than “Administrator”, then this is a finding.'
  desc 'fix', 'Configure the system to rename the built-in administrator account.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-411r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1115'
  tag rid: 'SV-1115r1_rule'
  tag gtitle: 'Rename Built-in Administrator Account'
  tag fix_id: 'F-5762r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
end
