control 'SV-35958' do
  title 'Unauthorized accounts must not have the Replace a process level token user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Replace a process level token" user right allows one process or service to start another process or service with a different security access token.  A user with this right could use this to impersonate another account.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Replace a process level token" right, this is a finding:

Local Service
Network Service'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Replace a process level token" to only include the following accounts or groups:

Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60893r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26503'
  tag rid: 'SV-35958r2_rule'
  tag stig_id: 'WINUR-000039'
  tag gtitle: 'Replace a process level token'
  tag fix_id: 'F-65625r2_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
