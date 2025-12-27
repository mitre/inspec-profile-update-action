control 'SV-216076' do
  title 'X displays must not be exported to the world.'
  desc 'Open X displays allow an attacker to capture keystrokes and to execute commands remotely. Many users have their X Server set to xhost +, permitting access to the X Server by anyone, from anywhere.'
  desc 'check', 'If X Windows is not used on the system, this is not applicable.

Check the output of the xhost command from an X terminal.

Procedure:
$ xhost
If the output reports access control is enabled (and possibly lists the hosts that can receive X Window logins), this is not a finding. If the xhost command returns a line indicating access control is disabled, this is a finding.

NOTE: It may be necessary to define the display if the command reports it cannot open the display. 

Procedure:
$ DISPLAY=MachineName:0.0; export DISPLAY
MachineName may be replaced with an Internet Protocol Address. Repeat the check procedure after setting the display.'
  desc 'fix', "If using an xhost-type authentication the xhost - command can be used to remove current trusted hosts and then selectively allow only trusted hosts to connect with xhost + commands. A cryptographically secure authentication, such as provided by the xauth program, is always preferred. Refer to your X11 server's documentation for further security information."
  impact 0.7
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17314r372610_chk'
  tag severity: 'high'
  tag gid: 'V-216076'
  tag rid: 'SV-216076r603268_rule'
  tag stig_id: 'SOL-11.1-020530'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17312r372611_fix'
  tag 'documentable'
  tag legacy: ['V-61025', 'SV-75493']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
