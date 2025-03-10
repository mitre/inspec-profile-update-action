control 'SV-215684' do
  title 'The Cisco router must be configured to enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

aaa new-model
!
!
aaa common-criteria policy PASSWORD_POLICY
 numeric-count 1

If the Cisco router is not configured to enforce password complexity by requiring that at least one numeric character be used, this is a finding.'
  desc 'fix', 'Configure the Cisco router to enforce password complexity by requiring that at least one numeric character be used as shown in the example below.

R1(config)#aaa common-criteria policy PASSWORD_POLICY
R1(config-cc-policy)#numeric-count 1
R1(config-cc-policy)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16878r286014_chk'
  tag severity: 'medium'
  tag gid: 'V-215684'
  tag rid: 'SV-215684r879605_rule'
  tag stig_id: 'CISC-ND-000590'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-16876r286015_fix'
  tag 'documentable'
  tag legacy: ['SV-105215', 'V-96077']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
