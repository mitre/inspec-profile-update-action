control 'SV-255954' do
  title 'The Arista network device must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the Arista device configuration "show management security" to determine the minimum 15-character password length.

 switch#show run | section management security
management security
   password minimum length 15
!

If the Arista network device does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the Arista device to enforce a minimum password 15-character length.

 switch#configure
switch(config)#management security
switch(config-mgmt-security)#password minimum length 15
switch(config-mgmt-security)#exit
switch(config)#
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59630r882202_chk'
  tag severity: 'medium'
  tag gid: 'V-255954'
  tag rid: 'SV-255954r882204_rule'
  tag stig_id: 'ARST-ND-000380'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-59573r882203_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
