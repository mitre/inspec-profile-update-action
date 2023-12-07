control 'SV-205662' do
  title 'Windows Server 2019 minimum password length must be configured to 14 characters.'
  desc 'Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password length," is less than "14" characters, this is a finding.

For server core installations, run the following command:

Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt

If "MinimumPasswordLength" is less than "14" in the file, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum password length" to "14" characters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5927r354904_chk'
  tag severity: 'medium'
  tag gid: 'V-205662'
  tag rid: 'SV-205662r569188_rule'
  tag stig_id: 'WN19-AC-000070'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-5927r354905_fix'
  tag 'documentable'
  tag legacy: ['V-93463', 'SV-103549']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
