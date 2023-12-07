control 'SV-216861' do
  title 'The vCenter Server for Windows passwords must contain at least one lowercase character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. 

The following password requirement should be set at a minimum: 
Lower-case Characters: At least 1 

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. Click "Edit". Set Lower-case Characters to at least "1" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18092r366297_chk'
  tag severity: 'medium'
  tag gid: 'V-216861'
  tag rid: 'SV-216861r879604_rule'
  tag stig_id: 'VCWN-65-000041'
  tag gtitle: 'SRG-APP-000167'
  tag fix_id: 'F-18090r366298_fix'
  tag 'documentable'
  tag legacy: ['SV-104617', 'V-94787']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
