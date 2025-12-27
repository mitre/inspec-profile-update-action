control 'SV-218573' do
  title 'X displays must not be exported to the world.'
  desc 'Open X displays allow an attacker to capture keystrokes and to execute commands remotely. Many users have their X Server set to "xhost +", permitting access to the X Server by anyone, from anywhere.'
  desc 'check', 'If Xwindows is not used on the system, this is not applicable.

Check the output of the "xhost" command from an X terminal.

Procedure:
# xhost
If the output reports access control is enabled (and possibly lists the hosts able to receive X window logins), this is not a finding. If the xhost command returns a line indicating access control is disabled, this is a finding.

Note: It may be necessary to define the display if the command reports it cannot open the display. 

Procedure:
$ DISPLAY=MachineName:0.0; export DISPLAY
MachineName may be replaced with an Internet Protocol Address. Repeat the check procedure after setting the display.'
  desc 'fix', %q(If using an xhost-type authentication the "xhost -" command can be used to remove current trusted hosts and then selectively allow only trusted hosts to connect with "xhost +" commands. A cryptographically secure authentication, such as provided by the xauth program, is always preferred.

Refer to your X11 server's documentation for further security information.)
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20048r555917_chk'
  tag severity: 'high'
  tag gid: 'V-218573'
  tag rid: 'SV-218573r603259_rule'
  tag stig_id: 'GEN005200'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20046r555918_fix'
  tag 'documentable'
  tag legacy: ['V-4697', 'SV-63295']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
