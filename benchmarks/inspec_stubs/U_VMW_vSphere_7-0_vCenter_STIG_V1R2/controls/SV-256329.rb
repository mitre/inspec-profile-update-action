control 'SV-256329' do
  title 'The vCenter Server passwords must contain at least one numeric character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy. 

Set the following password requirement with at least the stated value: 

Numeric Characters: At least 1 

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit".

Set "Numeric Characters" to at least "1" and click "Save".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCenter'
  tag check_id: 'C-60004r885596_chk'
  tag severity: 'medium'
  tag gid: 'V-256329'
  tag rid: 'SV-256329r885598_rule'
  tag stig_id: 'VCSA-70-000073'
  tag gtitle: 'SRG-APP-000168'
  tag fix_id: 'F-59947r885597_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
