control 'SV-39583' do
  title 'Unauthorized accounts will not have the "Add workstations to domain” user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Add workstations to domain” right may add computers to a domain.  This could result in unapproved or incorrectly configured systems being added to a domain.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the “Add workstations to domain” right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Add workstations to domain” as defined in the Check section.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-38497r1_chk'
  tag severity: 'medium'
  tag gid: 'V-30016'
  tag rid: 'SV-39583r1_rule'
  tag stig_id: 'WINUR-000043-AD'
  tag gtitle: 'Add workstations to domain'
  tag fix_id: 'F-33755r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
