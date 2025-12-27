control 'SV-248675' do
  title 'OL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for command line sessions.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, OL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen.

'
  desc 'check', %q(Verify the operating system enables the user to manually initiate a session lock with the following command:

     $ sudo grep -Ei 'lock-command|lock-session' /etc/tmux.conf

     set -g lock-command vlock
     bind X lock-session

If the "lock-command" is not set and "lock-session" is not bound to a specific keyboard key in the global settings, this is a finding.)
  desc 'fix', 'Configure the operating system to enable a user to manually initiate a session lock via tmux. This configuration binds the uppercase letter "X" to manually initiate a session lock after the prefix key "Ctrl + b" has been sent. The complete key sequence is thus "Ctrl + b" then "Shift + x" to lock tmux.

Create a global configuration file "/etc/tmux.conf" and add the following lines:

     set -g lock-command vlock
     bind X lock-session

Reload tmux configuration to take effect. This can be performed in tmux while it is running:

     $ tmux source-file /etc/tmux.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52109r902785_chk'
  tag severity: 'medium'
  tag gid: 'V-248675'
  tag rid: 'SV-248675r902786_rule'
  tag stig_id: 'OL08-00-020040'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-52063r880563_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
