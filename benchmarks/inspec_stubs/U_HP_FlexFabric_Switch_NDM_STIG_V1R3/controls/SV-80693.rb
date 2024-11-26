control 'SV-80693' do
  title 'The HP FlexFabric Switch must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Determine if the HP FlexFabric Switch or its associated authentication server enforces a minimum 15-character password length.

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled
 Password aging:                      Enabled (90 days)
 Password length:                     Enabled (15 characters)

If the HP FlexFabric Switch or its associated authentication server does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch or its associated authentication server to enforce a minimum 15-character password length.

[HP] password-control enable
[HP] password-control length 15'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66849r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66203'
  tag rid: 'SV-80693r1_rule'
  tag stig_id: 'HFFS-ND-000053'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-72279r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
