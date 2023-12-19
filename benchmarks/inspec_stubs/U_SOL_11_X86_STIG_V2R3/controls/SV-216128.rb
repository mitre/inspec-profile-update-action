control 'SV-216128' do
  title 'The operating system must not allow logins for users with blank passwords.'
  desc 'If the password field is blank and the system does not enforce a policy that passwords are required, it could allow login without proper authentication of a user.'
  desc 'check', 'Determine if the system is enforcing a policy that passwords are required.

# grep ^PASSREQ /etc/default/login

If the command does not return:

PASSREQ=YES

this is a finding.'
  desc 'fix', 'The root role is required.

Modify the /etc/default/login file.

# pfedit /etc/default/login

Insert the line:

PASSREQ=YES'
  impact 0.7
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17366r372766_chk'
  tag severity: 'high'
  tag gid: 'V-216128'
  tag rid: 'SV-216128r603268_rule'
  tag stig_id: 'SOL-11.1-040480'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17364r372767_fix'
  tag 'documentable'
  tag legacy: ['SV-61015', 'V-48143']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
