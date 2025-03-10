control 'SV-220542' do
  title 'The Cisco switch must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

aaa new-model
!
!
aaa common-criteria policy PASSWORD_POLICY
 char-changes 8

If the Cisco switch is not configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to enforce password complexity by requiring that when a password is changed, the characters are changed in at least eight of the positions within the password as shown in the example below:

SW1(config)#aaa common-criteria policy PASSWORD_POLICY
SW1(config-cc-policy)#char-changes 8
SW1(config-cc-policy)#exit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22257r508570_chk'
  tag severity: 'medium'
  tag gid: 'V-220542'
  tag rid: 'SV-220542r879607_rule'
  tag stig_id: 'CISC-ND-000610'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-22246r508571_fix'
  tag 'documentable'
  tag legacy: ['SV-110539', 'V-101435']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
