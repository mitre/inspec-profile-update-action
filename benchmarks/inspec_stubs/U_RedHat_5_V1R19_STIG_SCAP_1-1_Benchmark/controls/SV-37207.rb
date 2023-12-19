control 'SV-37207' do
  title 'The X server must have the correct options enabled.'
  desc 'Without the correct options enabled, the Xwindows system would be less secure and there would be no screen timeout.'
  desc 'fix', 'Enable the following options: -audit (at level 4), -auth and -s with 15 minutes as the timeout value.

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
Edit or create a .xserverrc file in the users home directory containing the startup script for xinit.
This script must have an exec line with at least these options:

exec /usr/bin/X -audit 4 -s 15 -auth <Xauth file> &

The <Xauth file> is created using the "xauth" command and is customarily located in the users home directory with the name ".Xauthority".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1021'
  tag rid: 'SV-37207r1_rule'
  tag stig_id: 'GEN000000-LNX00360'
  tag gtitle: 'GEN000000-LNX00360'
  tag fix_id: 'F-31154r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
