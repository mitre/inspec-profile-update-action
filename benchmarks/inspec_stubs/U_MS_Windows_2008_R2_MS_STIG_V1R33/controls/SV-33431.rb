control 'SV-33431' do
  title 'Unauthorized accounts must not have the Lock pages in memory user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause performance issues or a DoS.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Lock pages in memory" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Lock pages in memory" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61347r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26494'
  tag rid: 'SV-33431r2_rule'
  tag stig_id: 'WINUR-000029'
  tag gtitle: 'Lock pages in memory'
  tag fix_id: 'F-66039r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If an application requires this user right, this can be downgraded to not a finding if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the ISSO.
The application account must meet requirements for application account passwords, such as length and required changes frequency (V-14271).'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
