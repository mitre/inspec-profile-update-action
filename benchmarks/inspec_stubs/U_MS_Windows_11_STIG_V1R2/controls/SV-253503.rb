control 'SV-253503' do
  title 'The "Perform volume maintenance tasks" user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations. They could potentially delete volumes, resulting in data loss or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Perform volume maintenance tasks" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Perform volume maintenance tasks" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56956r829591_chk'
  tag severity: 'medium'
  tag gid: 'V-253503'
  tag rid: 'SV-253503r829593_rule'
  tag stig_id: 'WN11-UR-000145'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56906r829592_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
