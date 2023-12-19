control 'SV-90805' do
  title 'The OS X system must be configured with the sudoers file configured to authenticate users on a per -tty basis.'
  desc %q(The "sudo" command must be configured to prompt for the administrator user's password at least once in each newly opened Terminal window or remote logon session, as this prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session to bypass the normal password prompt requirement. 

Without the "tty_tickets" option, all open local and remote logon sessions would be authenticated to use sudo without a password for the duration of the configured password timeout window.)
  desc 'check', 'To check if the "tty_tickets" option is set for "/usr/bin/sudo", run the following command:

/usr/bin/sudo /usr/bin/grep tty_tickets /etc/sudoers

If there is no result, this is a finding.'
  desc 'fix', 'Edit the "/etc/sudoers" file to contain the line:

Defaults tty_tickets

This line can be placed in the defaults section or at the end of the file.'
  impact 0.7
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75803r1_chk'
  tag severity: 'high'
  tag gid: 'V-76117'
  tag rid: 'SV-90805r1_rule'
  tag stig_id: 'AOSX-12-000995'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
