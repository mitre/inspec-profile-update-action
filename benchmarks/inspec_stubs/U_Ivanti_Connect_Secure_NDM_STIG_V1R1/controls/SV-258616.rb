control 'SV-258616' do
  title 'The ICS must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Verify the setting for "new password must differ from the previous password position" is checked.
2. Verify the value for the setting for "new password must differ from the previous password position" is set to "80".

If the ICS is not configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to Authentication >> Auth Servers >> Administrators.
1. Check the box for "new password must differ from the previous password position".
2. In the box, enter "8".
3. Click "Save Changes".'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62356r930534_chk'
  tag severity: 'medium'
  tag gid: 'V-258616'
  tag rid: 'SV-258616r930536_rule'
  tag stig_id: 'IVCS-NM-000460'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-62265r930535_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
