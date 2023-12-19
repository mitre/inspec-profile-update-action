control 'SV-37217' do
  title 'An X server must have none of the following options enabled: -ac, -core (except for debugging purposes), or -nolock.'
  desc 'These options will detract from the security of the Xwindows system.'
  desc 'check', 'If the "xorg-x11-server-Xorg" package is not installed, this is not applicable.

Verify the options of the running Xwindows server are correct.

Procedure:

Get the running xserver information

# ps -ef |grep X

If the response contains /usr/bin/Xorg:0 

      /usr/bin/Xorg:0 -br -audit 0 -auth /var/gdm/:0.Xauth -nolisten tcp vt7

this is indicative of Xorg starting through gdm. This is the default window manager on RHEL.

If the "-ac" option is found, this is a finding.
If the "-core" option is found, this is a finding.
If the "-nolock" option is found, this is a finding.


If the response to the grep contains X:0 

/usr/bin/X:0

Examine the X:0 line:

If the "-ac" option is found, this is a finding.
If the "-core" option is found, this is a finding.
If the "-nolock" option is found, this is a finding.'
  desc 'fix', 'Disable the unwanted options: 
Procedure:
For gdm:
Remove the -ac, -core and -nolock options by creating a "command" entry in the /etc/gdm/custom.conf file with the options removed.

For Xwindows started by xinit:
Create or modify the .xserverrc script in the users home directory to remove the -ac, -core and -nolock options from the exec /usr/bin/X command.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35904r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1022'
  tag rid: 'SV-37217r2_rule'
  tag stig_id: 'GEN000000-LNX00380'
  tag gtitle: 'GEN000000-LNX00380'
  tag fix_id: 'F-31162r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
