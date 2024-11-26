control 'SV-48517' do
  title 'Unauthorized accounts must not have the Profile single process user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Profile single process" user right can monitor non-system processes performance. An attacker could potentially use this to identify processes to attack.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Profile single process" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Profile single process" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45168r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26500'
  tag rid: 'SV-48517r2_rule'
  tag stig_id: 'WN08-UR-000036'
  tag gtitle: 'Profile single process'
  tag fix_id: 'F-41640r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
