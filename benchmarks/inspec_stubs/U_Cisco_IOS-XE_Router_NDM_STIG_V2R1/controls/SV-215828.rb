control 'SV-215828' do
  title 'The Cisco router must be configured to enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

aaa new-model
!
!
aaa common-criteria policy PASSWORD_POLICY
lower-case 1

If the Cisco router is not configured to enforce password complexity by requiring that at least one lower-case character be used, this is a finding.'
  desc 'fix', 'Configure the Cisco router to enforce password complexity by requiring that at least one lower-case character be used as shown in the example below.

R1(config)#aaa common-criteria policy PASSWORD_POLICY
R1(config-cc-policy)#lower-case 1
R1(config-cc-policy)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17067r287523_chk'
  tag severity: 'medium'
  tag gid: 'V-215828'
  tag rid: 'SV-215828r531083_rule'
  tag stig_id: 'CISC-ND-000580'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-17065r287524_fix'
  tag 'documentable'
  tag legacy: ['V-96257', 'SV-105395']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
