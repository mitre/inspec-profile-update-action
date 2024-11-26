control 'SV-48493' do
  title 'Unauthorized accounts must not have the Create symbolic links user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Create symbolic links" user right can create pointers to other objects, which could potentially expose the system to attack.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create symbolic links" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Create symbolic links" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45150r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26482'
  tag rid: 'SV-48493r2_rule'
  tag stig_id: 'WN08-UR-000015'
  tag gtitle: 'Create symbolic links'
  tag fix_id: 'F-41616r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
