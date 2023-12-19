control 'SV-254291' do
  title 'Windows Server 2022 minimum password length must be configured to 14 characters.'
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
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57776r848687_chk'
  tag severity: 'medium'
  tag gid: 'V-254291'
  tag rid: 'SV-254291r890539_rule'
  tag stig_id: 'WN22-AC-000070'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-57727r848688_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
