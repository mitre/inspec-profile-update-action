control 'SV-47108' do
  title 'The Deny log on locally user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on locally" right defines accounts that are prevented from logging on interactively.  

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on locally" right, this is a finding:

Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on locally" to include the following.

Guests Group'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-44736r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26485'
  tag rid: 'SV-47108r1_rule'
  tag stig_id: 'WINUR-000020-DC'
  tag gtitle: 'Deny log on locally'
  tag fix_id: 'F-41036r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
