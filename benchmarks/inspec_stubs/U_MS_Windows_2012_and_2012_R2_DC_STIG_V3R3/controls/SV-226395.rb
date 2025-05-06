control 'SV-226395' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28098r477031_chk'
  tag severity: 'medium'
  tag gid: 'V-226395'
  tag rid: 'SV-226395r794666_rule'
  tag stig_id: 'WN12-UR-000035'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28086r477032_fix'
  tag 'documentable'
  tag legacy: ['SV-53025', 'V-26499']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
