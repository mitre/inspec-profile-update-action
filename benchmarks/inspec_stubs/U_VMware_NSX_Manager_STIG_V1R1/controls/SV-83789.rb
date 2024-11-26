control 'SV-83789' do
  title 'If multifactor authentication is not supported and passwords must be used, the NSX vCenter must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. The following password requirements should be set at a minimum: Special Characters: At least "1"

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

Click "Edit". Set Special Characters to at least "1" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69185'
  tag rid: 'SV-83789r1_rule'
  tag stig_id: 'VNSX-ND-000060'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-75371r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
