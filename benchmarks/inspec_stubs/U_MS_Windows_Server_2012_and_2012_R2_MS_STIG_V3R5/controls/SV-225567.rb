control 'SV-225567' do
  title 'The Load and unload device drivers user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Load and unload device drivers" user right allows device drivers to dynamically be loaded on a system by a user.  This could potentially be used to install malicious code by an attacker.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Load and unload device drivers" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Load and unload device drivers" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27266r472043_chk'
  tag severity: 'medium'
  tag gid: 'V-225567'
  tag rid: 'SV-225567r852280_rule'
  tag stig_id: 'WN12-UR-000028'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27254r472044_fix'
  tag 'documentable'
  tag legacy: ['SV-53043', 'V-26493']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
