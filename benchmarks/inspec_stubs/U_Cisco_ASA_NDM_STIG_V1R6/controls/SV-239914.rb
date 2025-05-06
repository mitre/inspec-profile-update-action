control 'SV-239914' do
  title 'The Cisco ASA must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the ASA configuration to verify that it is compliant with this requirement as shown in the example below.

password-policy minimum-length 15

If the ASA is not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to enforce password complexity by requiring a minimum 15-character password length as shown in the example below.

ASA(config)# password-policy minimum-length 15'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43147r666103_chk'
  tag severity: 'medium'
  tag gid: 'V-239914'
  tag rid: 'SV-239914r879601_rule'
  tag stig_id: 'CASA-ND-000490'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-43106r666104_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
