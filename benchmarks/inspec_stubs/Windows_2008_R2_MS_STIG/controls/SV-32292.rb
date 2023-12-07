control 'SV-32292' do
  title 'The built-in guest account will be renamed.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not renamed or disabled.  The built-in guest account is a known user account on all Windows systems, and as initially installed, does not require a password.  This can allow access to system resources by unauthorized users.  This account is a member of the group Everyone and has all the rights and permissions associated with that group and could provide access to system resources to unauthorized users.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Accounts: Rename guest account” is not set to a value other than “Guest”, then this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Accounts: Rename guest account” to a value other than “Guest”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-403r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1114'
  tag rid: 'SV-32292r1_rule'
  tag gtitle: 'Rename Built-in Guest Account'
  tag fix_id: 'F-28806r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
