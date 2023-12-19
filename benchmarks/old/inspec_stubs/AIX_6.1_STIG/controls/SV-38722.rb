control 'SV-38722' do
  title 'Xserver login managers must not be running unless needed for X11 session management.'
  desc 'Running Xservers and X-login managers when not needed for X11 session management increases the attack vector of the system by running unnecessary services.'
  desc 'check', 'Check to see if X display login managers are running.

#cat /etc/inittab | grep -e /etc/rc.dt -e xdm

If any X server login managers are running,  ask the SA if they are necessary for the operation of the system.  

If there is unnecessary X server login managers running, this is a finding.'
  desc 'fix', 'Comment out or remove  the X login servers from the /etc/inittab file.

#vi /etc/inittab 

Refresh the init process.

# init q'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37818r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29518'
  tag rid: 'SV-38722r1_rule'
  tag stig_id: 'GEN009340'
  tag gtitle: 'GEN009340'
  tag fix_id: 'F-33076r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
