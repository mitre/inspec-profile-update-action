control 'SV-35924' do
  title 'Unauthorized accounts must not have the Access Credential Manager as a trusted caller user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Access Credential Manager as a trusted caller" user right may be able to retrieve the credentials of other accounts from Credential Manager.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups are granted the "Access Credential Manager as a trusted caller" right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access Credential Manager as a trusted caller" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60821r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26469'
  tag rid: 'SV-35924r2_rule'
  tag stig_id: 'WINUR-000001'
  tag gtitle: 'Access Credential Manager as a trusted caller'
  tag fix_id: 'F-65553r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
