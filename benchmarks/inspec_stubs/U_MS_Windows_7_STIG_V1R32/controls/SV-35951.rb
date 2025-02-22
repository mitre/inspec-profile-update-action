control 'SV-35951' do
  title 'Unauthorized accounts must not have the Manage auditing and security log user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations.  This could be used to clear evidence of tampering.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Manage auditing and security log" right, this is a finding:

Administrators

If the organization has an "Auditors" group from previous requirements, the assignment of this group to the user right would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Manage auditing and security log" to only include the following accounts or groups:

Administrators

If the organization has an "Auditors" group from previous requirements, this group may be assigned the user right.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62243r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26496'
  tag rid: 'SV-35951r3_rule'
  tag stig_id: 'WINUR-000032'
  tag gtitle: 'Manage auditing and security log'
  tag fix_id: 'F-67159r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000171', 'CCI-001914']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 b', 'AU-12 (3)']
end
