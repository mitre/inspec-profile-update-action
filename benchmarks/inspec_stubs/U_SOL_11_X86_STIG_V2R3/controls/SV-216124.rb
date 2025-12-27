control 'SV-216124' do
  title 'Logins to the root account must be restricted to the system console only.'
  desc 'Use an authorized mechanism such as RBAC and the "su" command to provide administrative access to unprivileged accounts. These mechanisms provide an audit trail in the event of problems.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine if root login is restricted to the console.

# grep "^CONSOLE=/dev/console" /etc/default/login

If the output of this command is not:

CONSOLE=/dev/console

this is a finding.'
  desc 'fix', 'The root role is required.

Modify the /etc/default/login file

# pfedit /etc/default/login

Locate the line containing:

CONSOLE

Change it to read:

CONSOLE=/dev/console'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17362r372754_chk'
  tag severity: 'medium'
  tag gid: 'V-216124'
  tag rid: 'SV-216124r603268_rule'
  tag stig_id: 'SOL-11.1-040430'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17360r372755_fix'
  tag 'documentable'
  tag legacy: ['SV-60999', 'V-48127']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
