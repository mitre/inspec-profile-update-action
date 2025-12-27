control 'SV-253504' do
  title 'The "Profile single process" user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Profile single process" user right can monitor non-system processes performance. An attacker could potentially use this to identify processes to attack.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Profile single process" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Profile single process" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56957r829594_chk'
  tag severity: 'medium'
  tag gid: 'V-253504'
  tag rid: 'SV-253504r877392_rule'
  tag stig_id: 'WN11-UR-000150'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56907r829595_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
