control 'SV-216097' do
  title 'The system must not have accounts configured with blank or null passwords.'
  desc 'Complex passwords can reduce the likelihood of success of automated password-guessing attacks.'
  desc 'check', 'The root role is required.

Determine if accounts with blank or null passwords exist.

# logins -po

If any account is listed, this is a finding.'
  desc 'fix', 'The root role is required.

Remove, lock, or configure a password for any account with a blank password.

# passwd [username]
or
Use the passwd -l command to lock accounts that are not permitted to execute commands. 
or
Use the passwd -N command to set accounts to be non-login.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17335r372673_chk'
  tag severity: 'medium'
  tag gid: 'V-216097'
  tag rid: 'SV-216097r603268_rule'
  tag stig_id: 'SOL-11.1-040120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17333r372674_fix'
  tag 'documentable'
  tag legacy: ['V-47999', 'SV-60871']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
