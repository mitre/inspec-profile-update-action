control 'SV-225572' do
  title 'The Profile single process user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Profile single process" user right can monitor nonsystem processes performance.  An attacker could potentially use this to identify processes to attack.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Profile single process" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Profile single process" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27271r472058_chk'
  tag severity: 'medium'
  tag gid: 'V-225572'
  tag rid: 'SV-225572r852285_rule'
  tag stig_id: 'WN12-UR-000036'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27259r472059_fix'
  tag 'documentable'
  tag legacy: ['SV-53022', 'V-26500']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
