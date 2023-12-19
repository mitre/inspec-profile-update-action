control 'SV-88693' do
  title 'If multifactor authentication is not supported and passwords must be used, the Cisco IOS XE router must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to use complex passwords.

The configuration should look similar to the example below:

aaa common-criteria policy PASSWORD_POLICY
 min-length 15
 numeric-count 1
 upper-case 1
 lower-case 1
 special-case 1

If the use of complex passwords is not configured, this is a finding.'
  desc 'fix', 'Use the following commands to configure password complexity:  

aaa common-criteria policy PASSWORD_POLICY
 min-length 15
 numeric-count 1
 upper-case 1
 lower-case 1
 special-case 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74107r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74019'
  tag rid: 'SV-88693r2_rule'
  tag stig_id: 'CISR-ND-000060'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-80561r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
