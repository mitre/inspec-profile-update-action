control 'SV-220541' do
  title 'The Cisco switch must be configured to enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

aaa new-model
!
!
aaa common-criteria policy PASSWORD_POLICY
 special-case 1

If the Cisco switch is not configured to enforce password complexity by requiring that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to enforce password complexity by requiring that at least one special character be used as shown in the example below:

SW1(config)#aaa common-criteria policy PASSWORD_POLICY
SW1(config-cc-policy)#special-case 1
SW1(config-cc-policy)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22256r508567_chk'
  tag severity: 'medium'
  tag gid: 'V-220541'
  tag rid: 'SV-220541r508569_rule'
  tag stig_id: 'CISC-ND-000600'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag fix_id: 'F-22245r508568_fix'
  tag 'documentable'
  tag legacy: ['SV-110537', 'V-101433']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
