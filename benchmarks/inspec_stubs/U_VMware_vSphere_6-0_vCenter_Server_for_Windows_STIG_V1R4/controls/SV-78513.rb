control 'SV-78513' do
  title 'Passwords must contain at least one special character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  View the values of the password format requirements.

The following password requirements should be set at a minimum:

Special Characters: At least 1

If this password complexity policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  Click Edit. Set Special Characters to at least 1 and click OK.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64023'
  tag rid: 'SV-78513r1_rule'
  tag stig_id: 'VCWN-06-000043'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-69953r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
