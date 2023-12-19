control 'SV-33386' do
  title 'Unauthorized accounts must not have the Create a pagefile user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system performance.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create a pagefile" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a pagefile" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61061r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26478'
  tag rid: 'SV-33386r2_rule'
  tag stig_id: 'WINUR-000011'
  tag gtitle: 'Create a pagefile'
  tag fix_id: 'F-65795r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
