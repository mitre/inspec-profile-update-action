control 'SV-1022' do
  title 'An X server must have none of the following options enabled: -ac, -core (except for debugging purposes), or -nolock.'
  desc 'These options will detract from the security of the Xwindows system.'
  desc 'check', 'X servers get started several ways, such as xdm, gdm or xinit.  Perform:
	#	ps –ef |grep X

Output for example:

	/usr/X11R6/bin/X –nolisten –ctp –br vt7 –auth /var/lib/xdm/authdir/authfiles/A:0

The above example show xdm is controlling the Xserver.

Check the Xservers file to ensure the following options are not enabled:
-ac, -core, and -nolock .

Xserver files can found in:

/etc/X11/xdm/Xservers
/etc/opt/kde3/share/config/kdm/Xservers
/etc/X11/gdm/Xservers'
  desc 'fix', 'Disable the following options:  -ac, -core and -nolock.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8302r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1022'
  tag rid: 'SV-1022r2_rule'
  tag stig_id: 'GEN000000-LNX00380'
  tag gtitle: 'GEN000000-LNX00380'
  tag fix_id: 'F-1176r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
