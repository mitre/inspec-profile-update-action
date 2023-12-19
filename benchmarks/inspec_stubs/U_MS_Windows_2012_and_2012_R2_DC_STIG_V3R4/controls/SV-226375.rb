control 'SV-226375' do
  title 'The Create a pagefile user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system performance.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create a pagefile" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create a pagefile" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28078r476971_chk'
  tag severity: 'medium'
  tag gid: 'V-226375'
  tag rid: 'SV-226375r794652_rule'
  tag stig_id: 'WN12-UR-000011'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28066r476972_fix'
  tag 'documentable'
  tag legacy: ['SV-53063', 'V-26478']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
