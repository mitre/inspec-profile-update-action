control 'SV-246853' do
  title 'The HYCU server must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Log on to the HYCU VM console. Check for the value of the "minclass" option in "/etc/security/pwquality.conf" with the following command:
grep mincla /etc/security/pwquality.conf 

If the minclass value is not set to "5", this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a minimum class setting.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value).
minclass = 5'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50285r768221_chk'
  tag severity: 'medium'
  tag gid: 'V-246853'
  tag rid: 'SV-246853r768223_rule'
  tag stig_id: 'HYCU-IA-000005'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-50239r768222_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
