control 'SV-216862' do
  title 'The vCenter Server for Windows passwords must contain at least one numeric character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. 

The following password requirement should be set at a minimum: 
Numeric Characters: At least 1 

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. Click "Edit". Set Numeric Characters to at least "1" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18093r366300_chk'
  tag severity: 'medium'
  tag gid: 'V-216862'
  tag rid: 'SV-216862r612237_rule'
  tag stig_id: 'VCWN-65-000042'
  tag gtitle: 'SRG-APP-000168'
  tag fix_id: 'F-18091r366301_fix'
  tag 'documentable'
  tag legacy: ['SV-104619', 'V-94789']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
