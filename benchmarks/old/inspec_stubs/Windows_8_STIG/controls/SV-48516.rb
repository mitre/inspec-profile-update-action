control 'SV-48516' do
  title 'Unauthorized accounts must not have the Profile system performance user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Profile system performance" user right can monitor system processes performance. An attacker could potentially use this to identify processes to attack.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Profile system performance" user right, this is a finding:

Administrators
NT Service\\WdiServiceHost'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Profile system performance" to only include the following accounts or groups:

Administrators
NT Service\\WdiServiceHost'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45166r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26501'
  tag rid: 'SV-48516r2_rule'
  tag stig_id: 'WN08-UR-000037'
  tag gtitle: 'Profile system performance'
  tag fix_id: 'F-41638r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
