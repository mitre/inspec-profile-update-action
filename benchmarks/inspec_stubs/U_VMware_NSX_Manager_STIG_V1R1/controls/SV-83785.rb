control 'SV-83785' do
  title 'If multifactor authentication is not supported and passwords must be used, the NSX vCenter must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 
 
Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. The following password requirement should be set at a minimum: Lower-case Characters: At least "1" 

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

Click "Edit". Set Lower-case Characters to at least "1" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69621r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69181'
  tag rid: 'SV-83785r1_rule'
  tag stig_id: 'VNSX-ND-000058'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-75367r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
