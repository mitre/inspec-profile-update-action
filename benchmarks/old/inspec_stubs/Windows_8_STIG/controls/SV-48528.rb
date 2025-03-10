control 'SV-48528' do
  title 'Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45179r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26487'
  tag rid: 'SV-48528r2_rule'
  tag stig_id: 'WN08-UR-000022'
  tag gtitle: 'Enable accounts to be trusted for delegation'
  tag fix_id: 'F-41651r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
