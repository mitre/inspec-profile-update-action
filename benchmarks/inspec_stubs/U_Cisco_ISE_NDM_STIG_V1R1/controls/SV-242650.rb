control 'SV-242650' do
  title 'For accounts using password authentication, the Cisco ISE must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Verify that at least eight is required for the password delta.

Show password policy

If the Cisco ISE password policy is not configured to require at least eight for the password delta, this is a finding.'
  desc 'fix', 'Configure the password policy.

password-policy password-delta 8'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45925r714258_chk'
  tag severity: 'medium'
  tag gid: 'V-242650'
  tag rid: 'SV-242650r714260_rule'
  tag stig_id: 'CSCO-NM-000450'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-45882r714259_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
