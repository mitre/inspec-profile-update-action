control 'SV-25024' do
  title 'The built-in guest account must be renamed.'
  desc 'The built-in guest account is a well-known user account on all Windows systems and, as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Accounts: Rename guest account" is not set to a value other than "Guest", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Rename guest account" to a name other than "Guest".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60779r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1114'
  tag rid: 'SV-25024r2_rule'
  tag gtitle: 'Rename Built-in Guest Account'
  tag fix_id: 'F-65511r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
