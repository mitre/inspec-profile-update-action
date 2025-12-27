control 'SV-88695' do
  title 'If multifactor authentication is not supported and passwords must be used, the CCisco IOS XE router must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to use complex passwords.

The configuration should look similar to the example below:

aaa common-criteria policy PASSWORD_POLICY
 min-length 15
 numeric-count 1
 upper-case 1
 lower-case 1
 special-case 1
 char-changes 8

If the use of complex passwords is not configured, this is a finding.'
  desc 'fix', 'Use the following commands to configure password complexity:  

aaa common-criteria policy PASSWORD_POLICY
 min-length 15
 numeric-count 1
 upper-case 1
 lower-case 1
 special-case 1
 char-changes 8'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74111r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74021'
  tag rid: 'SV-88695r2_rule'
  tag stig_id: 'CISR-ND-000061'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-80563r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
