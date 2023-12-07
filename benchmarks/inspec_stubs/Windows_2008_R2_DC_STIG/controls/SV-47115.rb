control 'SV-47115' do
  title 'The Deny log on as a batch job user right on domain controllers must be configured to prevent unauthenticated access.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a batch job" right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.  

The Guests group must be assigned to prevent unauthenticated access.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a batch job" right, this is a finding.

Guests Group'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a batch job" to include the following.

Guests Group'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-44732r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26483'
  tag rid: 'SV-47115r1_rule'
  tag stig_id: 'WINUR-000018-DC'
  tag gtitle: 'Deny log on as a batch job'
  tag fix_id: 'F-41032r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
