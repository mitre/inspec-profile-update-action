control 'SV-1021' do
  title 'The X server must have the correct options enabled.'
  desc 'Without the correct options enabled, the Xwindows system would be less secure and there would be no screen timeout.'
  desc 'check', 'X servers get started several ways, such as xdm, gdm or xinit.  Perform:
	#	ps –ef |grep X

Output for example:

	/usr/X11R6/bin/X –nolisten –ctp –br vt7 –auth /var/lib/xdm/authdir/authfiles/A:0
 
Check the Xservers file to ensure the following options are enabled:

-audit, -auth, and –s 15.

Xserver files can found in:

/etc/X11/xdm/Xservers
/etc/opt/kde3/share/config/kdm/Xservers
/etc/X11/gdm/Xservers'
  desc 'fix', 'Enable the following options:  -audit (at level 4), -auth and -s with 15 minutes as the timeout value.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2042r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1021'
  tag rid: 'SV-1021r2_rule'
  tag stig_id: 'GEN000000-LNX00360'
  tag gtitle: 'GEN000000-LNX00360'
  tag fix_id: 'F-1175r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
