control 'SV-253496' do
  title 'The "Enable computer and user accounts to be trusted for delegation" user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56949r829570_chk'
  tag severity: 'medium'
  tag gid: 'V-253496'
  tag rid: 'SV-253496r829572_rule'
  tag stig_id: 'WN11-UR-000095'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56899r829571_fix'
  tag 'documentable'
  tag cci: ['CCI-002205']
  tag nist: ['AC-4 (17)']
end
