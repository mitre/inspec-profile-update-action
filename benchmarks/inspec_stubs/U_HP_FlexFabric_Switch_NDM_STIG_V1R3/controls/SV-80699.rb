control 'SV-80699' do
  title 'If multifactor authentication is not supported and passwords must be used, the HP FlexFabric Switch must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Check to see that the HP FlexFabric Switch enforces password complexity by requiring that at least one lower-case character be used.

[HP] display password-control

Global password control configurations:
 Password control:                    Enabled
 Password aging:                      Enabled (60 days)
 Password length:                     Enabled (15 characters)
 Password composition:                Enabled (4 types, 1 characters per type)

If the HP FlexFabric Switch does not require that at least one lower-case character be used in each password, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce password complexity by requiring that at least one lower-case character be used:

[HP] password-control enable
[HP] password-control composition enable
[HP] password-control composition type-number 4 type-length 2'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66209'
  tag rid: 'SV-80699r1_rule'
  tag stig_id: 'HFFS-ND-000056'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-72285r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
