control 'SV-225570' do
  title 'The Modify firmware environment values user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Modify firmware environment values" user right can change hardware configuration environment variables.  This could result in hardware failures or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Modify firmware environment values" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Modify firmware environment values" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27269r472052_chk'
  tag severity: 'medium'
  tag gid: 'V-225570'
  tag rid: 'SV-225570r569185_rule'
  tag stig_id: 'WN12-UR-000034'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27257r472053_fix'
  tag 'documentable'
  tag legacy: ['SV-53029', 'V-26498']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
