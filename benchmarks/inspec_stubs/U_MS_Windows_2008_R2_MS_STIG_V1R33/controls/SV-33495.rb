control 'SV-33495' do
  title 'Unauthorized accounts must not have the Restore files and directories user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Restore files and directories" user right can circumvent file and directory permissions and could allow access to sensitive data.  It could also be used to overwrite more current data.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Restore files and directories" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Restore files and directories" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61353r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26504'
  tag rid: 'SV-33495r2_rule'
  tag stig_id: 'WINUR-000040'
  tag gtitle: 'Restore files and directories'
  tag fix_id: 'F-66383r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If an application requires this user right, this can be downgraded to not a finding if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the ISSO.
The application account must meet requirements for application account passwords, such as length and required changes frequency (V-14271).'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
