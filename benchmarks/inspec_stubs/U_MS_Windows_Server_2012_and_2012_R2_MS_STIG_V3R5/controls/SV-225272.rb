control 'SV-225272' do
  title 'Passwords must, at a minimum, be 14 characters.'
  desc 'Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy.

If the value for the "Minimum password length," is less than "14" characters, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum password length" to "14" characters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26971r471158_chk'
  tag severity: 'medium'
  tag gid: 'V-225272'
  tag rid: 'SV-225272r569185_rule'
  tag stig_id: 'WN12-AC-000007'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-26959r471159_fix'
  tag 'documentable'
  tag legacy: ['SV-52938', 'V-6836']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
