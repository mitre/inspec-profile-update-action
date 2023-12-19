control 'SV-218169' do
  title 'The X server must have the correct options enabled.'
  desc 'Without the correct options enabled, the Xwindows system would be less secure and there would be no screen timeout.'
  desc 'check', 'Verify the options of the running Xwindows server are correct.

Procedure:
Get the running xserver information

# ps -ef |grep X

If the response contains /usr/bin/Xorg:0 

      /usr/bin/Xorg:0 -br -audit 0 -auth /var/gdm/:0.Xauth -nolisten tcp vt7

this is indicative of Xorg starting through gdm. This is the default on this version of the operating system.

Examine the Xorg line:

If the "-auth" option is missing this would be a finding.
If the "-audit" option is missing or not set to 4, this is a finding.
If the "-s" option is missing or greater than 15, this is a finding.


If the response to the grep contains X:0 

/usr/bin/X:0

this indicates the X server was started with the xinit command with no associated .xserverrc in the home directory of the user. No options are selected by default. This is a finding.

Otherwise if there are options on the X:0 line:
If the "-auth" option is missing this is a finding 
If the "-audit" option is missing or not set to 4, this is a finding.
If the "-s" option is missing or greater than 15, this is a finding.'
  desc 'fix', %q(Enable the following options: -audit (at level 4), -auth and -s with 15 minutes as the timeout value.

Procedure for gdm:
Edit /etc/gdm/custom.conf and add the following:
[server-Standard] 
name=Standard server
command=/usr/bin/Xorg -br -audit 4 -s 15
chooser=false
handled=true
flexible=true
priority=0

Procedure for xinit:
Edit or create a .xserverrc file in the user's home directory containing the startup script for xinit.
This script must have an exec line with at least these options:

exec /usr/bin/X -audit 4 -s 15 -auth <Xauth file> &

The <Xauth file> is created using the "xauth" command and is customarily located in the user's home directory with the name ".Xauthority".)
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19644r553844_chk'
  tag severity: 'medium'
  tag gid: 'V-218169'
  tag rid: 'SV-218169r603259_rule'
  tag stig_id: 'GEN000000-LNX00360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19642r553845_fix'
  tag 'documentable'
  tag legacy: ['V-1021', 'SV-62805']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
