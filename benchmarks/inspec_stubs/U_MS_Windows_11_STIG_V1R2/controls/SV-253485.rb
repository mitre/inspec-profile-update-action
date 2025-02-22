control 'SV-253485' do
  title 'The "Create a pagefile" user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system performance.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create a pagefile" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a pagefile" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56938r829537_chk'
  tag severity: 'medium'
  tag gid: 'V-253485'
  tag rid: 'SV-253485r829539_rule'
  tag stig_id: 'WN11-UR-000040'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56888r829538_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
