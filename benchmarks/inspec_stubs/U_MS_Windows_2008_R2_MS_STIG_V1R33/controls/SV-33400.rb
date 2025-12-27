control 'SV-33400' do
  title 'Unauthorized accounts must not have the Create symbolic links user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create symbolic links" right can create pointers to other objects which could potentially expose the system to attack.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the “Create symbolic links” right, this is a finding:

Administrators

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right (this may be displayed as "NT Virtual Machine\\Virtual Machines").  This is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create symbolic links" to only include the following accounts or groups:

Administrators

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right.  If this needs to be added manually, enter it as "NT Virtual Machine\\Virtual Machines".'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61323r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26482'
  tag rid: 'SV-33400r2_rule'
  tag stig_id: 'WINUR-000015'
  tag gtitle: 'Create symbolic links'
  tag fix_id: 'F-66015r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
