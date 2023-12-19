control 'SV-33414' do
  title 'Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed.  This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-33897r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26487'
  tag rid: 'SV-33414r2_rule'
  tag stig_id: 'WINUR-000022'
  tag gtitle: 'Enable accounts to be trusted for delegation'
  tag fix_id: 'F-65799r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
