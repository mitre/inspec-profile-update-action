control 'SV-225571' do
  title 'The Perform volume maintenance tasks user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations.  They could potentially delete volumes, resulting in data loss or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Perform volume maintenance tasks" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Perform volume maintenance tasks" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27270r472055_chk'
  tag severity: 'medium'
  tag gid: 'V-225571'
  tag rid: 'SV-225571r569185_rule'
  tag stig_id: 'WN12-UR-000035'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27258r472056_fix'
  tag 'documentable'
  tag legacy: ['SV-53025', 'V-26499']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
