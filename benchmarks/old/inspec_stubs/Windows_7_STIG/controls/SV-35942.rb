control 'SV-35942' do
  title 'Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed.  This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Enable computer and user accounts to be trusted for delegation" right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60861r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26487'
  tag rid: 'SV-35942r2_rule'
  tag stig_id: 'WINUR-000022'
  tag gtitle: 'Enable accounts to be trusted for delegation'
  tag fix_id: 'F-65593r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
