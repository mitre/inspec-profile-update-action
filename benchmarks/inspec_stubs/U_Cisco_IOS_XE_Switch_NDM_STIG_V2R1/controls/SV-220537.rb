control 'SV-220537' do
  title 'The Cisco switch must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

aaa new-model
!
!
aaa common-criteria policy PASSWORD_POLICY
 min-length 15

If the Cisco switch is not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to enforce a minimum 15-character password length as shown in the example below:

SW1(config)#aaa common-criteria policy PASSWORD_POLICY
SW1(config-cc-policy)#min-length 15
SW1(config-cc-policy)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22252r508555_chk'
  tag severity: 'medium'
  tag gid: 'V-220537'
  tag rid: 'SV-220537r531084_rule'
  tag stig_id: 'CISC-ND-000550'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-22241r508556_fix'
  tag 'documentable'
  tag legacy: ['SV-110529', 'V-101425']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
