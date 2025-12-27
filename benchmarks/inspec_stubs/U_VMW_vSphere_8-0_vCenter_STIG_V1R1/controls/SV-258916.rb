control 'SV-258916' do
  title 'The vCenter Server passwords must contain at least one special character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

View the value of the "Character requirements" setting.

Character requirements: At least 1 special characters

If the password policy is not configured with "Character requirements" policy requiring "1" or more special characters, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set "special characters" to at least "1" and click "Save".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62656r934404_chk'
  tag severity: 'medium'
  tag gid: 'V-258916'
  tag rid: 'SV-258916r934406_rule'
  tag stig_id: 'VCSA-80-000074'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-62565r934405_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
