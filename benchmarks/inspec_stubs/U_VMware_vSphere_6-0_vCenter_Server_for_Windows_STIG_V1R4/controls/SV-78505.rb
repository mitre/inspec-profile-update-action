control 'SV-78505' do
  title 'Passwords must be at least 15 characters in length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  View the values of the password format requirements.

The following password requirement should be set at a minimum:

Minimum Length: 15

If this password policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy.  Click Edit. Set the Minimum Length to 15 and click OK.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64015'
  tag rid: 'SV-78505r1_rule'
  tag stig_id: 'VCWN-06-000039'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-69945r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
