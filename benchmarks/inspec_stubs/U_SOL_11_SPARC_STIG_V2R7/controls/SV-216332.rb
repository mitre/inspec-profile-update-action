control 'SV-216332' do
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
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17568r371084_chk'
  tag severity: 'medium'
  tag gid: 'V-216332'
  tag rid: 'SV-216332r603267_rule'
  tag stig_id: 'SOL-11.1-040120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17566r371085_fix'
  tag 'documentable'
  tag legacy: ['SV-60871', 'V-47999']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
