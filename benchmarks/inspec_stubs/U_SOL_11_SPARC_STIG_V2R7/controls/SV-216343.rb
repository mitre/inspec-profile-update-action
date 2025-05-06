control 'SV-216343' do
  title 'The value mesg n must be configured as the default setting for all users.'
  desc %q(The "mesg n" command blocks attempts to use the "write" or "talk" commands to contact users at their terminals, but has the side effect of slightly strengthening permissions on the user's TTY device.)
  desc 'check', 'Determine if "mesg n" is the default for users.

# grep "^mesg" /etc/.login

# grep "^mesg" /etc/profile

If either of these commands produces a line:
mesg y

this is a finding.

For each existing user on the system, enter the command:

# mesg

If the command output is:
is y

this is a finding.'
  desc 'fix', 'The root role is required.

Edit the default profile configuration files.

# pfedit /etc/profile 
# pfedit /etc/.login

In each file add a new line:

mesg n

For each user on the system, enter the command:

# mesg n'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17579r371117_chk'
  tag severity: 'low'
  tag gid: 'V-216343'
  tag rid: 'SV-216343r603267_rule'
  tag stig_id: 'SOL-11.1-040270'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17577r371118_fix'
  tag 'documentable'
  tag legacy: ['V-48075', 'SV-60947']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
