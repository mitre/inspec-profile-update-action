control 'SV-35927' do
  title 'Unauthorized accounts will not have the "Allow log on locally" user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Allow log on locally" right can log on interactively to a system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on locally" user right, this is a finding:

Administrators
Users

Systems dedicated to managing Active Directory (AD admin platforms), must only allow Administrators, removing the Users group.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Allow log on locally" to only include the following accounts or groups:

Administrators
Users   

Systems dedicated to managing Active Directory (AD admin platforms), must only allow Administrators, removing the Users group.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-49423r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26472'
  tag rid: 'SV-35927r2_rule'
  tag stig_id: 'WINUR-000005'
  tag gtitle: 'Allow log on locally'
  tag fix_id: 'F-49514r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
