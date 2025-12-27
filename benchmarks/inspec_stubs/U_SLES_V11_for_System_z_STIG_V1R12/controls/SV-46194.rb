control 'SV-46194' do
  title 'The system must require passwords contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'check', 'Check the system password length setting.

Procedure:
Check the password minlen option
# grep pam_cracklib.so /etc/pam.d/ common-{auth,account,password,session}

Confirm the minlen option is set to at least 15 as in the example below:

password required pam_cracklib.so minlen=15

There may be other options on the line. If no such line is found, or the minlen is less than 15 this is a finding.'
  desc 'fix', 'Edit /etc/pam.d/common-password and add or edit a pam_cracklib.so entry with a minlen parameter set equal to or greater than 15.  

NOTE: /etc/pam.d/common-password is normally a symbolic link that points to common-password-pc or common-password-local, a file to be ‘included’ by other pam configuration files.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43423r7_chk'
  tag severity: 'medium'
  tag gid: 'V-11947'
  tag rid: 'SV-46194r2_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'GEN000580'
  tag fix_id: 'F-39526r6_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
