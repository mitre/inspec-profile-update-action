control 'SV-33381' do
  title 'The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-69277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26473'
  tag rid: 'SV-33381r3_rule'
  tag stig_id: 'WINUR-000006-DC'
  tag gtitle: 'Allow log on through Remote Desktop Services'
  tag fix_id: 'F-74881r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
