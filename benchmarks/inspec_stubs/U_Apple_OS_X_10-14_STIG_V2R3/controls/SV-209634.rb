control 'SV-209634' do
  title 'The macOS system must be configured with the sudoers file configured to authenticate users on a per -tty basis.'
  desc %q(The "sudo" command must be configured to prompt for the administrator's password at least once in each newly opened Terminal window or remote logon session, as this prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session to bypass the normal password prompt requirement. 

Without the "tty_tickets" option, all open local and remote logon sessions would be authenticated to use sudo without a password for the duration of the configured password timeout window.)
  desc 'check', 'To check if the "tty_tickets" option is set for "/usr/bin/sudo", run the following command:

/usr/bin/sudo /usr/bin/grep tty_tickets /etc/sudoers

If there is no result, this is a finding.'
  desc 'fix', 'Edit the "/etc/sudoers" file to contain the line:

Defaults tty_tickets

This line can be placed in the defaults section or at the end of the file.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9885r282384_chk'
  tag severity: 'high'
  tag gid: 'V-209634'
  tag rid: 'SV-209634r610285_rule'
  tag stig_id: 'AOSX-14-004021'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-9885r282385_fix'
  tag 'documentable'
  tag legacy: ['V-95587', 'SV-104733']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
