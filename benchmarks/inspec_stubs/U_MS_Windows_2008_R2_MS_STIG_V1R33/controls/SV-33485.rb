control 'SV-33485' do
  title 'Unauthorized accounts must not have the Modify an object label user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Modify an object label" user right can change the integrity label of an object.  This could potentially be used to execute code at a higher privilege.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Modify an object label" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Modify an object label" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61073r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26497'
  tag rid: 'SV-33485r2_rule'
  tag stig_id: 'WINUR-000033'
  tag gtitle: 'Modify an object label'
  tag fix_id: 'F-65809r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
