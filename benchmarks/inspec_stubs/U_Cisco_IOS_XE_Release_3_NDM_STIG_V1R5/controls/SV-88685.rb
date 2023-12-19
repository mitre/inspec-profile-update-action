control 'SV-88685' do
  title 'The Cisco IOS XE router must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify that the Cisco IOS XE router enforces a minimum password length of "15" characters.

The configuration should look similar to the example below:

aaa common-criteria policy <Policy Name> 
 min-length 15

If a minimum password length of "15" characters is not enforced, this is a finding.'
  desc 'fix', 'Use the following commands to configure minimum password length:

aaa common-criteria policy <Policy Name>
 min-length 15'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74097r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74011'
  tag rid: 'SV-88685r2_rule'
  tag stig_id: 'CISR-ND-000055'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-80553r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
