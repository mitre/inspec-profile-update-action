control 'SV-216859' do
  title 'The vCenter Server for Windows passwords must be at least 15 characters in length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. 

View the values of the password format requirements. 

The following password requirement should be set at a minimum: 
Minimum Length: 15 

If this password policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Password Policy. Click "Edit". Set the Minimum Length to "15" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18090r366291_chk'
  tag severity: 'medium'
  tag gid: 'V-216859'
  tag rid: 'SV-216859r879601_rule'
  tag stig_id: 'VCWN-65-000039'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-18088r366292_fix'
  tag 'documentable'
  tag legacy: ['SV-104613', 'V-94783']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
