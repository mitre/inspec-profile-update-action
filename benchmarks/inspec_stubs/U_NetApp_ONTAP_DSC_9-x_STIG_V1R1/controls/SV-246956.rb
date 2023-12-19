control 'SV-246956' do
  title 'ONTAP must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Use "security login show -role admin -authentication-method domain" to see all configured admin users and groups that authenticate using active directory.

If ONTAP does not require that when a password is changed, the characters are changed in at least eight of the positions within the password, this is a finding.'
  desc 'fix', 'Configure ONTAP users to authenticate using active directory to require that when a password is changed, the characters are changed in at least eight of the positions within the password.

New administrator active directory users or groups should be created with "security login create -user-or-group-name <user_name> -role admin -authentication-method domain" to make use of active directory to authenticate.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50388r769198_chk'
  tag severity: 'medium'
  tag gid: 'V-246956'
  tag rid: 'SV-246956r769200_rule'
  tag stig_id: 'NAOT-IA-000010'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-50342r769199_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
