control 'SV-48532' do
  title 'Unauthorized accounts must not have the Create global objects user right.'
  desc %q(Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Create global objects" user right can create objects that are available to all sessions, which could affect processes in other users' sessions.)
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create global objects" user right, this is a finding:

Administrators
Service
Local Service
Network Service'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Create global objects" to only include the following accounts or groups:

Administrators
Service
Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26480'
  tag rid: 'SV-48532r2_rule'
  tag stig_id: 'WN08-UR-000013'
  tag gtitle: 'Create global objects'
  tag fix_id: 'F-41655r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
