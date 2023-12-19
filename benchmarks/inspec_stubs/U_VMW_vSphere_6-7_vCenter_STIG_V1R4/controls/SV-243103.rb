control 'SV-243103' do
  title 'The vCenter Server passwords must contain at least one special character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. 

The following password requirements should be set at a minimum: 

Special Characters: At least 1 

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

Click "Edit". 

Set "Special Characters" to at least "1" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46378r719550_chk'
  tag severity: 'medium'
  tag gid: 'V-243103'
  tag rid: 'SV-243103r879606_rule'
  tag stig_id: 'VCTR-67-000043'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-46335r719551_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
