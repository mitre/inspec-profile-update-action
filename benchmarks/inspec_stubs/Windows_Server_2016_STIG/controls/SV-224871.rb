control 'SV-224871' do
  title 'Windows Server 2016 minimum password age must be configured to at least one day.'
  desc 'Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password age" is set to "0" days ("Password can be changed immediately"), this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "MinimumPasswordAge" equals "0" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum password age" to at least "1" day.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26562r465515_chk'
  tag severity: 'medium'
  tag gid: 'V-224871'
  tag rid: 'SV-224871r569186_rule'
  tag stig_id: 'WN16-AC-000060'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-26550r465516_fix'
  tag 'documentable'
  tag legacy: ['V-73319', 'SV-87971']
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
