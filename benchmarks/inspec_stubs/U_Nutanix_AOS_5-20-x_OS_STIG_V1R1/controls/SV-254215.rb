control 'SV-254215' do
  title 'Nutanix AOS must require the maximum number of repeating characters be limited to three when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least eight characters.'
  desc 'check', 'Verify Nutanix AOS is configured to require complex passwords.

$ sudo grep maxrepeat /etc/security/pwquality.conf 
maxrepeat = 2

If the value of "maxrepeat" is set to more than "2", this is a finding.'
  desc 'fix', 'Configure the complex password requirements by running the following command:

$ ncli cluster edit-cvm-security-params enable-high-strength-password=true'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57700r846731_chk'
  tag severity: 'medium'
  tag gid: 'V-254215'
  tag rid: 'SV-254215r846733_rule'
  tag stig_id: 'NUTX-OS-001300'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-57651r846732_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
