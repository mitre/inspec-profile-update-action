control 'SV-86157' do
  title 'If multifactor authentication is not supported and passwords must be used, the CA API Gateway must require that when a password is changed, the characters are changed in at least 8 of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify the password attribute "difok" field is set to "8" in the following files: 

-- /etc/pam.d/password-auth
-- /etc/pam.d/password-auth-ac

If the password attribute "difok" field is not set to "8" in these files, this is a finding.'
  desc 'fix', 'Set the password attribute "difok" field is set to "8" in the following files: 

-- /etc/pam.d/password-auth
-- /etc/pam.d/password-auth-ac'
  impact 0.5
  ref 'DPMS Target CA API Gateway NDM'
  tag check_id: 'C-71905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71533'
  tag rid: 'SV-86157r1_rule'
  tag stig_id: 'CAGW-DM-000170'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-77853r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
