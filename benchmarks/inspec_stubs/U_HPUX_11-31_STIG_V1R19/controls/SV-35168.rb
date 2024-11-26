control 'SV-35168' do
  title 'X displays must not be exported to the world.'
  desc 'Open X displays allow an attacker to capture keystrokes and to execute commands remotely. Many users have their X Server set to xhost +, permitting access to the X Server by anyone, from anywhere.'
  desc 'check', 'Windows is not used on the system, this is not applicable.

Check the output of the "xhost" command from an X terminal. First, verify the DISPLAY variable is correctly set.
$ echo $DISPLAY

NOTE: It may be necessary to define the display if the command reports it cannot open the display. 
MachineName may be replaced with an Internet Protocol Address. Repeat the check procedure after setting the display.
$ DISPLAY=MachineName:0.0; export DISPLAY
$ xhost

If the output reports access control is enabled (and possibly lists the hosts that can receive X window logins), this is not a finding. If the xhost command returns a line indicating access control is disabled, this is a finding.'
  desc 'fix', 'If using an xhost-type authentication the xhost - command can be used to remove current trusted hosts and then selectively allow only trusted hosts to connect with xhost + commands. A cryptographically secure authentication, such as provided by the xauth program, is always preferred.'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36601r1_chk'
  tag severity: 'high'
  tag gid: 'V-4697'
  tag rid: 'SV-35168r1_rule'
  tag stig_id: 'GEN005200'
  tag gtitle: 'GEN005200'
  tag fix_id: 'F-31968r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
