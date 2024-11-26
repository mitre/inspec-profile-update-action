control 'SV-243101' do
  title 'The vCenter Server passwords must contain at least one lowercase character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. 

The following password requirement should be set at a minimum: 

Lower-case Characters: At least 1 

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

Click "Edit". 

Set "Lower-case Characters" to at least "1" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46376r719544_chk'
  tag severity: 'medium'
  tag gid: 'V-243101'
  tag rid: 'SV-243101r719546_rule'
  tag stig_id: 'VCTR-67-000041'
  tag gtitle: 'SRG-APP-000167'
  tag fix_id: 'F-46333r719545_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
