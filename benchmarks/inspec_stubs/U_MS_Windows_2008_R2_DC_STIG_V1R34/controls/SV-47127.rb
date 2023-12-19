control 'SV-47127' do
  title 'The Deny log on as a service user right must be configured to include no accounts or groups (blank).'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Deny log on as a service" right defines accounts that are denied log on as a service.  

Incorrect configurations could prevent services from starting and result in a DoS.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups are defined for the "Deny log on as a service" right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-44744r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26484'
  tag rid: 'SV-47127r1_rule'
  tag stig_id: 'WINUR-000019-DC'
  tag gtitle: 'Deny log on as service'
  tag fix_id: 'F-41044r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
