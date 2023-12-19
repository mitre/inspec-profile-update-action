control 'SV-33384' do
  title 'Unauthorized accounts must not have the Change the system time user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Change the system time" user right can change the system time, which can impact authentication, as well as affect time stamps on event log entries.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Change the system time" user right, this is a finding:

Administrators
Local Service'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Change the system time" to only include the following accounts or groups:

Administrators
Local Service'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-60995r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26476'
  tag rid: 'SV-33384r2_rule'
  tag stig_id: 'WINUR-000009'
  tag gtitle: 'Change the system time'
  tag fix_id: 'F-65725r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
