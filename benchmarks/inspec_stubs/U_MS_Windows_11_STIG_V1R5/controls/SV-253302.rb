control 'SV-253302' do
  title 'The minimum password age must be configured to at least 1 day.'
  desc 'Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password age" is less than "1" day, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum Password Age" to at least "1" day.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56755r828988_chk'
  tag severity: 'medium'
  tag gid: 'V-253302'
  tag rid: 'SV-253302r828990_rule'
  tag stig_id: 'WN11-AC-000030'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-56705r828989_fix'
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
