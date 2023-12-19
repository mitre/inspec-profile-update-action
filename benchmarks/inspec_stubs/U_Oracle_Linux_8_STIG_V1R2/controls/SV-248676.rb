control 'SV-248676' do
  title 'OL 8 must ensure session control is automatically started at shell initialization.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, OL 8 needs to provide users with the ability to manually invoke a session lock so users can secure their session if it is necessary to temporarily vacate the immediate physical vicinity.

Tmux is a terminal multiplexer that enables a number of terminals to be created, accessed, and controlled from a single screen.

'
  desc 'check', 'Verify the operating system shell initialization file is configured to start each shell with the tmux terminal multiplexer with the following commands:

Determine if tmux is currently running:

$ sudo ps all | grep tmux | grep -v grep

If the command does not produce output, this is a finding.
 
Determine the location of the tmux script:

$ sudo grep tmux /etc/profile.d/*
/etc/profile.d/tmux.sh:  case "$name" in (sshd|login) exec tmux ;; esac

Review the tmux script by using the following example:
$ sudo cat /etc/profile.d/tmux.sh
if [ "$PS1" ]; then
	parent=$(ps -o ppid= -p $$)
	name=$(ps -o comm= -p $parent)
	case "$name" in (sshd|login) exec tmux ;; esac
fi

If "tmux" is not configured as the example above, is commented out or missing, this is a finding.'
  desc 'fix', 'Configure the operating system to initialize the tmux terminal multiplexer as each shell is called by adding the following lines to a custom.sh shell script in the /etc/profile.d/ directory:

if [ "$PS1" ]; then
	parent=$(ps -o ppid= -p $$)
	name=$(ps -o comm= -p $parent)
	case "$name" in (sshd|login) exec tmux ;; esac
fi

This setting will take effect at next logon.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52110r818651_chk'
  tag severity: 'medium'
  tag gid: 'V-248676'
  tag rid: 'SV-248676r818653_rule'
  tag stig_id: 'OL08-00-020041'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-52064r818652_fix'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011']
  tag 'documentable'
  tag cci: ['CCI-000056', 'CCI-000058']
  tag nist: ['AC-11 b', 'AC-11 a']
end
