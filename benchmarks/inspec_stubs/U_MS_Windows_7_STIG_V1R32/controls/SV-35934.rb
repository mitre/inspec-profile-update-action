control 'SV-35934' do
  title 'Unauthorized accounts must not have the Create a token object user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Create a token object" user right allows a process to create an access token.  This could be used to provide elevated rights and compromise a system.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Create a token object" right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a token object" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60839r2_chk'
  tag severity: 'high'
  tag gid: 'V-26479'
  tag rid: 'SV-35934r2_rule'
  tag stig_id: 'WINUR-000012'
  tag gtitle: 'Create a token object'
  tag fix_id: 'F-65571r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
