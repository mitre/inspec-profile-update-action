control 'SV-237140' do
  title 'ColdFusion must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Controlling what a user can see or change is important within the ColdFusion application server.  Allowing non-privileged users to change administrative type data can cause errors within the system or DoS situations.  By forcing users to identify themselves and then tying roles to that identity, an individual is presented with only those options needed to perform their duties.'
  desc 'check', 'Within the Administrator Console, navigate to the "User Manager" page under the "Security" menu.  Review the roles assigned to each user against the ISSM approved list of user accounts and roles to determine if any user has excessive authorization.

 If any user has roles assigned that are not approved by the ISSM, this is a finding.'
  desc 'fix', 'Navigate to the "User Manager" page under the "Security" menu and review the roles assigned to each user.  Enable only those roles for each user approved by the ISSO/ISSM.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40359r641513_chk'
  tag severity: 'medium'
  tag gid: 'V-237140'
  tag rid: 'SV-237140r641515_rule'
  tag stig_id: 'CF11-01-000007'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-40322r641514_fix'
  tag 'documentable'
  tag legacy: ['SV-76843', 'V-62353']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
